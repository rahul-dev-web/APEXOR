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
