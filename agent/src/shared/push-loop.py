# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
async def _keepalive_loop(ws: WebSocket) -> None:
    """Ping periodically (NAT keepalive) and detect a dead peer.

    If nothing has arrived from the server for _RECV_TIMEOUT (no pong, no data),
    the connection is dead (backend restart / half-open TCP) — raise so the main
    loop tears down and reconnects instead of hanging on a silent socket.
    """
    while True:
        await asyncio.sleep(_PING_INTERVAL)
        if ws.stale_seconds() > _RECV_TIMEOUT:
            raise WSError(f"no data from server in {_RECV_TIMEOUT}s — dead connection")
        await ws.ping()


def _apply_push_interval(value: object) -> None:
    """Apply a dashboard-pinned push cadence to the live config.

    The push loop reads ``cfg.push_interval`` each cycle, so mutating the shared
    ``_STATE.config`` takes effect on the next push. Ignores junk and guards against
    a 0/negative value that would turn the push loop into a hot loop.
    """
    cfg = _STATE.config
    if value is None or cfg is None:
        return
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return
    if seconds < 1 or seconds == cfg.push_interval:
        return
    cfg.push_interval = seconds
    log.info("push interval set to %ds (dashboard)", seconds)


async def _push_loop(ws: WebSocket, cfg: Config) -> None:
    """Push metrics snapshot every N seconds.

    The initial random sleep spreads the fleet's push phase across the interval:
    a backend restart drops every agent at once and they all reconnect within the
    same backoff window — without the jitter the whole fleet then pushes in the
    same second, every cycle, in lockstep (INSERT spikes on the dashboard DB).
    Capped at 30s so a large operator-set interval can't delay first data past
    the dashboard's stale threshold (120s).
    """
    await asyncio.sleep(random.uniform(0, min(cfg.push_interval, 30)))
    while True:
        try:
            snapshot = await asyncio.get_event_loop().run_in_executor(None, collect_all)
        except Exception as exc:
            # A single collector raising must NOT kill the push loop — that would
            # take the agent silent (dashboard: "agent silent for >120s") over one
            # bad field. Skip this cycle, keep the loop (and liveness) alive.
            log.warning("metrics collection failed, skipping cycle: %s", exc)
        else:
            try:
                await ws.send(json.dumps({"type": "metrics", "data": snapshot}))
                log.debug("pushed metrics snapshot")
            except Exception as exc:
                # Send failure means the socket is gone — let it propagate so the
                # outer connection loop reconnects.
                log.warning("push error: %s", exc)
                raise
        await asyncio.sleep(cfg.push_interval)
