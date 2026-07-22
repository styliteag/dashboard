# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
async def _probation_watchdog(healthy: asyncio.Event) -> None:
    """If we just self-updated, demand a healthy reconnect or roll back."""
    try:
        await asyncio.wait_for(healthy.wait(), _PROBATION_SECS)
    except asyncio.TimeoutError:
        log.error(
            "self-update: probation FAILED (no healthy connect in %ds), rolling back",
            _PROBATION_SECS,
        )
        _rollback()
        os._exit(1)
