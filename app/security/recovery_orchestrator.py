from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import discord
from sqlalchemy import select

from app.database.session import SessionLocal
from app.models.events import SecurityIncident
from app.security.recovery import RecoveryEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RecoveryJob:
    guild_id: int
    resource_type: str
    resource_id: int
    reason: str
    priority: int = 100


class RecoveryOrchestrator:
    """Single-worker, priority-aware, rate-limit-aware recovery queue.

    Detection stays on the Gateway callback path; Discord mutations happen here
    so a burst of destructive events cannot create uncontrolled concurrent REST
    calls. Duplicate events for the same resource are coalesced while a recovery
    job is queued or executing. The queue is intentionally in-memory for the MVP
    and can later be replaced by Redis/Render queue infrastructure without
    changing callers.
    """

    def __init__(
        self,
        *,
        max_queue_size: int = 512,
        max_attempts: int = 4,
        recovery_spacing: float = 0.05,
        retry_cap: float = 30.0,
    ) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, int, RecoveryJob]] = asyncio.PriorityQueue(maxsize=max_queue_size)
        self._sequence = 0
        self._worker: asyncio.Task[None] | None = None
        self._stopping = False
        self._recovery = RecoveryEngine()
        self._max_attempts = max(1, max_attempts)
        self._recovery_spacing = max(0.0, recovery_spacing)
        self._retry_cap = max(0.1, retry_cap)
        self._last_request_at = 0.0
        self._pending_keys: set[tuple[int, str, int]] = set()

    @staticmethod
    def _job_key(guild_id: int, resource_type: str, resource_id: int) -> tuple[int, str, int]:
        return guild_id, resource_type.upper(), resource_id

    async def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._stopping = False
            self._worker = asyncio.create_task(self._run(), name="apxor-recovery-worker")
            logger.info("Recovery orchestrator started")

    async def stop(self) -> None:
        self._stopping = True
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass
            self._worker = None
        # Cancelled jobs must not permanently block future recovery attempts.
        self._pending_keys.clear()
        logger.info("Recovery orchestrator stopped")

    async def enqueue(
        self,
        *,
        guild_id: int,
        resource_type: str,
        resource_id: int,
        reason: str,
        priority: int = 100,
    ) -> bool:
        if self._stopping:
            return False
        await self.start()

        key = self._job_key(guild_id, resource_type, resource_id)
        if key in self._pending_keys:
            logger.info(
                "Duplicate recovery coalesced: guild=%s resource=%s/%s",
                guild_id,
                resource_type,
                resource_id,
            )
            return False

        job = RecoveryJob(
            guild_id=guild_id,
            resource_type=resource_type.upper(),
            resource_id=resource_id,
            reason=reason,
            priority=priority,
        )
        self._sequence += 1
        try:
            self._queue.put_nowait((priority, self._sequence, job))
            self._pending_keys.add(key)
            logger.warning(
                "Recovery queued: guild=%s resource=%s/%s priority=%s",
                guild_id,
                resource_type,
                resource_id,
                priority,
            )
            return True
        except asyncio.QueueFull:
            logger.critical(
                "Recovery queue full: guild=%s resource=%s/%s",
                guild_id,
                resource_type,
                resource_id,
            )
            return False

    async def _run(self) -> None:
        while True:
            _priority, _sequence, job = await self._queue.get()
            key = self._job_key(job.guild_id, job.resource_type, job.resource_id)
            try:
                await self._execute_with_retry(job)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "Unhandled recovery job failure: guild=%s resource=%s/%s",
                    job.guild_id,
                    job.resource_type,
                    job.resource_id,
                )
            finally:
                self._pending_keys.discard(key)
                self._queue.task_done()

    async def _execute_with_retry(self, job: RecoveryJob) -> None:
        for attempt in range(1, self._max_attempts + 1):
            try:
                await self._pace_recovery_requests()
                await self._execute(job)
                return
            except discord.RateLimited as exc:
                if attempt >= self._max_attempts:
                    logger.error(
                        "Recovery exhausted rate-limit retries: guild=%s resource=%s/%s",
                        job.guild_id,
                        job.resource_type,
                        job.resource_id,
                    )
                    raise
                delay = min(max(float(exc.retry_after), 0.0), self._retry_cap)
                logger.warning(
                    "Discord rate limit during recovery; retrying in %.2fs (attempt %s/%s): guild=%s resource=%s/%s",
                    delay,
                    attempt,
                    self._max_attempts,
                    job.guild_id,
                    job.resource_type,
                    job.resource_id,
                )
                await asyncio.sleep(delay)
            except discord.HTTPException as exc:
                if not 500 <= exc.status < 600 or attempt >= self._max_attempts:
                    raise
                delay = min(2 ** (attempt - 1), self._retry_cap)
                logger.warning(
                    "Transient Discord HTTP error during recovery; retrying in %.2fs (attempt %s/%s): status=%s guild=%s resource=%s/%s",
                    delay,
                    attempt,
                    self._max_attempts,
                    exc.status,
                    job.guild_id,
                    job.resource_type,
                    job.resource_id,
                )
                await asyncio.sleep(delay)

    async def _pace_recovery_requests(self) -> None:
        if self._recovery_spacing <= 0:
            self._last_request_at = asyncio.get_running_loop().time()
            return

        loop = asyncio.get_running_loop()
        now = loop.time()
        remaining = self._recovery_spacing - (now - self._last_request_at)
        if remaining > 0:
            await asyncio.sleep(remaining)
        self._last_request_at = loop.time()

    async def _execute(self, job: RecoveryJob) -> None:
        guild = _guild_from_client(job.guild_id)
        if guild is None:
            logger.error("Recovery skipped: guild not cached: %s", job.guild_id)
            return
        if SessionLocal is None:
            logger.error("Recovery skipped: database is not configured")
            return

        async with SessionLocal() as session:
            incident = await self._find_recovery_incident(session, job)
            if incident is not None:
                incident.recovery_status = "IN_PROGRESS"
                incident.recovery_started_at = incident.recovery_started_at or datetime.now(timezone.utc)
                incident.updated_at = datetime.now(timezone.utc)
                await session.flush()
                await session.commit()

            action = await self._recovery.restore_resource(
                session,
                guild,
                resource_type=job.resource_type,
                resource_id=job.resource_id,
                reason=job.reason,
            )
            now = datetime.now(timezone.utc)
            if incident is not None:
                if action.status == "VERIFIED":
                    incident.recovery_status = "VERIFIED"
                    incident.recovered_at = now
                    incident.status = "RESOLVED"
                    incident.resolved_at = now
                elif action.status in {"FAILED", "VERIFICATION_FAILED"}:
                    incident.recovery_status = "FAILED"
                incident.updated_at = now
                await session.commit()

            logger.info(
                "Recovery completed: guild=%s resource=%s/%s status=%s restored=%s incident=%s",
                job.guild_id,
                job.resource_type,
                job.resource_id,
                action.status,
                action.restored_resource_id,
                incident.incident_key if incident is not None else None,
            )

    @staticmethod
    async def _find_recovery_incident(session, job: RecoveryJob) -> SecurityIncident | None:
        family = "CHANNEL_NUKE" if job.resource_type == "CHANNEL" else "ROLE_NUKE"
        return await session.scalar(
            select(SecurityIncident)
            .where(
                SecurityIncident.guild_id == job.guild_id,
                SecurityIncident.incident_type == family,
                SecurityIncident.status == "OPEN",
            )
            .order_by(SecurityIncident.created_at.desc())
            .limit(1)
        )


# Injected by APXORClient at startup. Keeping the orchestrator independent from
# discord.Client avoids a circular dependency between security and bot layers.
_discord_client: discord.Client | None = None


def bind_discord_client(client: discord.Client) -> None:
    global _discord_client
    _discord_client = client


def _guild_from_client(guild_id: int) -> discord.Guild | None:
    return _discord_client.get_guild(guild_id) if _discord_client is not None else None
