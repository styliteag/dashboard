#!/bin/sh
# run-agent.sh — supervisor for the orbit agent (DR-5).
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

AGENT="${AGENT_PATH:-/usr/local/orbit-agent/orbit_agent.py}"
PY="${1:-}"
# Resolve a Python 3 interpreter without hardcoding the version. OPNsense ships
# /usr/local/bin/python3; pfSense may install only a versioned binary and the
# version varies by release (python3.8 on older boxes, 3.11+ on newer, etc).
# Prefer an unversioned python3, else pick the NEWEST python3.N found.
if [ -z "${PY}" ]; then
    for _d in /usr/local/bin /usr/bin; do
        if [ -x "${_d}/python3" ]; then PY="${_d}/python3"; break; fi
        _cand=$(ls "${_d}"/python3.* 2>/dev/null | grep -E '/python3\.[0-9]+$' | sort -t. -k2 -rn | head -1)
        if [ -n "${_cand}" ] && [ -x "${_cand}" ]; then PY="${_cand}"; break; fi
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
        logger -t orbit_agent \
            "self-update rollback: agent exited rc=${rc} after ${runtime}s; restored backup"
    fi
    sleep 2
done
