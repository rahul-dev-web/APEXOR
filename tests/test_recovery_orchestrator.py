import pytest

from app.security.recovery_orchestrator import RecoveryJob, RecoveryOrchestrator


@pytest.mark.asyncio
async def test_recovery_orchestrator_processes_priority_order() -> None:
    orchestrator = RecoveryOrchestrator()
    processed: list[RecoveryJob] = []

    async def fake_execute(job: RecoveryJob) -> None:
        processed.append(job)

    orchestrator._execute = fake_execute  # type: ignore[method-assign]

    await orchestrator.start()
    try:
        await orchestrator.enqueue(
            guild_id=1,
            resource_type="CHANNEL",
            resource_id=101,
            reason="normal recovery",
            priority=50,
        )
        await orchestrator.enqueue(
            guild_id=1,
            resource_type="ROLE",
            resource_id=202,
            reason="protected recovery",
            priority=10,
        )
        await orchestrator._queue.join()

        assert [job.resource_id for job in processed] == [202, 101]
        assert processed[0].priority == 10
    finally:
        await orchestrator.stop()


@pytest.mark.asyncio
async def test_recovery_orchestrator_coalesces_duplicate_resource_jobs() -> None:
    orchestrator = RecoveryOrchestrator()
    processed: list[RecoveryJob] = []

    async def fake_execute(job: RecoveryJob) -> None:
        processed.append(job)
        await pytest.importorskip("asyncio").sleep(0)

    orchestrator._execute = fake_execute  # type: ignore[method-assign]

    await orchestrator.start()
    try:
        first = await orchestrator.enqueue(
            guild_id=1,
            resource_type="CHANNEL",
            resource_id=101,
            reason="first event",
        )
        duplicate = await orchestrator.enqueue(
            guild_id=1,
            resource_type="CHANNEL",
            resource_id=101,
            reason="duplicate event",
        )
        assert first is True
        assert duplicate is False

        await orchestrator._queue.join()
        assert len(processed) == 1
    finally:
        await orchestrator.stop()


@pytest.mark.asyncio
async def test_recovery_orchestrator_stops_accepting_jobs_after_stop() -> None:
    orchestrator = RecoveryOrchestrator()
    await orchestrator.start()
    await orchestrator.stop()

    accepted = await orchestrator.enqueue(
        guild_id=1,
        resource_type="CHANNEL",
        resource_id=101,
        reason="late job",
    )

    assert accepted is False


@pytest.mark.asyncio
async def test_recovery_orchestrator_retries_rate_limited_jobs(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRateLimited(Exception):
        def __init__(self, retry_after: float) -> None:
            self.retry_after = retry_after

    monkeypatch.setattr("app.security.recovery_orchestrator.discord.RateLimited", FakeRateLimited)

    orchestrator = RecoveryOrchestrator(max_attempts=3, recovery_spacing=0, retry_cap=5)
    attempts = 0
    sleeps: list[float] = []

    async def fake_execute(job: RecoveryJob) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise FakeRateLimited(0.25)

    orchestrator._execute = fake_execute  # type: ignore[method-assign]

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("app.security.recovery_orchestrator.asyncio.sleep", fake_sleep)

    await orchestrator._execute_with_retry(
        RecoveryJob(
            guild_id=1,
            resource_type="CHANNEL",
            resource_id=101,
            reason="rate-limit test",
        )
    )

    assert attempts == 2
    assert sleeps == [0.25]
