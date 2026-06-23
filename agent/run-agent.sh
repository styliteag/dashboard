#!/bin/sh
# run-agent.sh — supervisor for the opnsense-dash agent (DR-5).
#
# Plain daemon(8) (no -r) does not respawn, so this wrapper provides both the
# respawn loop and the self-update rollback that make self-update safe:
#
#   - exit 42  → intentional self-update restart: respawn into the new code,
#                no rollback (the new agent then proves itself via probation).
#   - other exit, marker present, ran < MIN_HEALTHY, backup exists → the new
#     agent crashed fast: restore the backup before respawning.
#
# rc.d runs this instead of python directly and passes the interpreter as $1.

set -u

AGENT="${AGENT_PATH:-/usr/local/opnsense-dash-agent/opnsense_agent.py}"
PY="${1:-}"
if [ -z "${PY}" ]; then
    for _py in /usr/local/bin/python3 /usr/local/bin/python3.11 \
               /usr/local/bin/python3.10 /usr/local/bin/python3.9; do
        [ -x "${_py}" ] && PY="${_py}" && break
    done
fi

MARKER="${AGENT}.updating"
BAK="${AGENT}.bak"
MIN_HEALTHY=60

child=""
term() {
    [ -n "${child}" ] && kill "${child}" 2>/dev/null
    exit 0
}
trap term TERM INT

while true; do
    start=$(date +%s)
    "${PY}" "${AGENT}" &
    child=$!
    wait "${child}"
    rc=$?
    end=$(date +%s)

    # Intentional self-update restart → respawn into the new code, no rollback.
    if [ "${rc}" -eq 42 ]; then
        continue
    fi

    runtime=$((end - start))
    if [ -f "${MARKER}" ] && [ "${runtime}" -lt "${MIN_HEALTHY}" ] && [ -f "${BAK}" ]; then
        cp "${BAK}" "${AGENT}"
        rm -f "${MARKER}"
        logger -t opnsense_dash_agent \
            "self-update rollback: agent exited rc=${rc} after ${runtime}s; restored backup"
    fi
    sleep 2
done
