"""Route-inventory drift detector.

docs/api-contract/openapi.json is the frozen inventory of paths+methods.
Routes appearing or vanishing without a deliberate snapshot refresh fail here.

Refresh (only when a route change is intended, same commit):

    python3 - <<'EOF'
    import json, urllib.request
    d = json.load(urllib.request.urlopen("http://localhost:8000/openapi.json"))
    with open("docs/api-contract/openapi.json", "w") as f:
        f.write(json.dumps(d, indent=2, sort_keys=True) + "\n")
    EOF
"""

import json
from pathlib import Path

import pytest

SNAPSHOT = Path(__file__).resolve().parent.parent / "docs" / "api-contract" / "openapi.json"


def test_route_inventory_matches_snapshot(anon):
    live_resp = anon.get("/openapi.json")
    if live_resp.status_code == 404:
        pytest.skip("backend under test exposes no /openapi.json (server_ex)")

    live = live_resp.json()["paths"]
    snap = json.loads(SNAPSHOT.read_text())["paths"]

    assert set(live) == set(snap), (
        f"route drift — added: {sorted(set(live) - set(snap))}, "
        f"removed: {sorted(set(snap) - set(live))}"
    )
    for path, methods in snap.items():
        assert set(live[path]) == set(methods), f"method drift on {path}"
