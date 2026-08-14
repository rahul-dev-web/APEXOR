from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import discord

from app.database.session import SessionLocal
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
    """Single-worker, priority-aware recovery queue.

    Detection stays on the Gateway callback path; Discord mutations happen here
    so a burst of destructive events cannot create uncontrolled concurrent REST
    calls. The queue is intentionally in-memory for the MVP and can later be
    replaced by Redis/Render queue infrastructure without changing callers.
    """

    def __init__(self, *, max_queue_size: int = 512) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, int, RecoveryJob]] = asyncio.PriorityQueue(maxsize=max_queue_size)
        self._sequence = 0
        self._worker: asyncio.Task[None] | None = None
        self._stopping = False
        self._recovery = RecoveryEngine()

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
        self._sequence += 1
        try:
            self._queue.put_nowait((priority, self._sequence, RecoveryJob(
                guild_id=guild_id,
                resource_type=resource_type,
                resource_id=resource_id,
                reason=reason,
                priority=priority,
            )))
            logger.warning(
                "Recovery queued: guild=%s resource=%s/%s priority=%s",
                guild_id, resource_type, resource_id, priority,
            )
            return True
        except asyncio.QueueFull:
            logger.critical("Recovery queue full: guild=%s resource=%s/%s", guild_id, resource_type, resource_id)
            return False

    async def _run(self) -> None:
        while True:
            _priority, _sequence, job = await self._queue.get()
            try:
                await self._execute(job)
            except Exception:
                logger.exception(
                    "Unhandled recovery job failure: guild=%s resource=%s/%s",
                    job.guild_id, job.resource_type, job.resource_id,
                )
            finally:
                self._queue.task_done()

    async def _execute(self, job: RecoveryJob) -> None:
        guild = _guild_from_client(job.guild_id)
        if guild is None:
            logger.error("Recovery skipped: guild not cached: %s", job.guild_id)
            return
        if SessionLocal is None:
            logger.error("Recovery skipped: database is not configured")
            return

        async with SessionLocal() as session:
            action = await self._recovery.restore_resource(
                session,
                guild,
                resource_type=job.resource_type,
                resource_id=job.resource_id,
                reason=job.reason,
            )
            logger.info(
                "Recovery completed: guild=%s resource=%s/%s status=%s restored=%s",
                job.guild_id,
                job.resource_type,
                job.resource_id,
                action.status,
                action.restored_resource_id,
            )


# Injected by APXORClient at startup. Keeping the orchestrator independent from
# discord.Client avoids a circular dependency between security and bot layers.
_discord_client: discord.Client | None = None


def bind_discord_client(client: discord.Client) -> None:
    global _discord_client
    _discord_client = client


def _guild_from_client(guild_id: int) -> discord.Guild | None:
    return _discord_client.get_guild(guild_id) if _discord_client is not None else None
