"""Checkmk-agent output → snapshot enrichment (agent_hub/checkmk.py, §25/DR-10).

Pins the contract between the vendored check_mk_agent.linux output and the
payload shapes status_from_agent expects, so drift on either side is caught.
DB-free: everything under test is pure.
"""

from __future__ import annotations

import base64
import gzip

from app.agent_hub.checkmk import (
    cpu_pct_from_ticks,
    decode_raw,
    enrich_snapshot,
    parse_sections,
)
from app.agent_hub.converters import status_from_agent

_SAMPLE = """<<<check_mk>>>
Version: 2.5.0p8
AgentOS: linux
<<<cpu>>>
0.26 0.28 0.30 2/1052 29319 8
<<<kernel>>>
1752230000
cpu  1000 0 500 8000 500 0 0 0 0 0
ctxt 987654
<<<mem>>>
MemTotal:       16314912 kB
MemFree:         5000000 kB
MemAvailable:   12236184 kB
Buffers:          500000 kB
Cached:          4000000 kB
SwapTotal:       2097148 kB
SwapFree:        1048574 kB
<<<df>>>
/dev/sda1      ext4   41152736 20576368 18455636      53% /
/dev/sdb1      xfs   103081248 10308124 92773124      10% /srv/data mount
tmpfs          tmpfs   8157456        0  8157456       0% /dev/shm
[df_inodes_start]
/dev/sda1      ext4  2621440  300000 2321440      12% /
[df_inodes_end]
<<<uptime>>>
1067020.61 8412618.16
<<<systemd_units>>>
[list-unit-files]
ssh.service enabled enabled
"""


def _payload(text: str = _SAMPLE) -> dict:
    raw = text.encode()
    return {
        "checkmk_raw": {
            "sha256": "x",
            "size": len(raw),
            "output_gz_b64": base64.b64encode(gzip.compress(raw)).decode(),
        },
        # What the orbit collectors produce on linux: junk/zero sections.
        "cpu": {"total_pct": 0.0},
        "memory": {"total_mb": 0, "used_mb": 0, "used_pct": 0},
        "loadavg": {"one": 0.0, "five": 0.0, "fifteen": 0.0, "cores": 0},
        "disks": [],
        "uptime": "",
        "system": {"hostname": "srv1", "platform": "linux"},
    }


def test_decode_raw_roundtrip_and_absent() -> None:
    assert decode_raw(_payload()).startswith("<<<check_mk>>>")
    assert decode_raw({}) is None
    assert decode_raw({"checkmk_raw": {}}) is None
    assert decode_raw({"checkmk_raw": {"output_gz_b64": "not-base64!!"}}) is None


def test_parse_sections_splits_and_skips_piggyback() -> None:
    text = (
        "<<<cpu>>>\n1 2 3\n<<<<otherhost>>>>\n<<<mem>>>\nMemTotal: 1 kB\n"
        "<<<<>>>>\n<<<uptime>>>\n60\n"
    )
    sections = parse_sections(text)
    assert sections["cpu"] == ["1 2 3"]
    assert "mem" not in sections  # piggybacked to another host
    assert sections["uptime"] == ["60"]


def test_parse_sections_first_occurrence_wins() -> None:
    text = "<<<cpu>>>\n1 2 3\n<<<cpu>>>\n9 9 9\n"
    assert parse_sections(text)["cpu"] == ["1 2 3"]


def test_parse_sections_drops_header_options() -> None:
    text = "<<<logwatch:sep(124):cached(1,2)>>>\nline\n"
    assert parse_sections(text)["logwatch"] == ["line"]


def test_enrich_maps_load_mem_df_uptime() -> None:
    data = _payload()
    out, ticks = enrich_snapshot(data, parse_sections(decode_raw(data)), None)

    assert out["loadavg"] == {"one": 0.26, "five": 0.28, "fifteen": 0.30, "cores": 8}
    mem = out["memory"]
    assert mem["total_mb"] == round(16314912 / 1024, 1)
    # used = MemTotal - MemAvailable
    assert mem["used_mb"] == round((16314912 - 12236184) / 1024, 1)
    assert mem["swap_used_pct"] == 50.0
    # tmpfs filtered, inode block skipped, space in mountpoint preserved
    assert [d["mountpoint"] for d in out["disks"]] == ["/", "/srv/data mount"]
    assert out["disks"][0]["used_pct"] == 53.0
    # 1067020s = 12 days, 8:23
    assert out["uptime"] == "12 days, 8:23"
    assert ticks == (10000, 8500)
    # First push: no previous ticks → cpu stays the orbit zero value.
    assert out["cpu"] == {"total_pct": 0.0}


def test_enrich_never_mutates_the_input_payload() -> None:
    data = _payload()
    before = {k: (dict(v) if isinstance(v, dict) else v) for k, v in data.items()}
    enrich_snapshot(data, parse_sections(decode_raw(data)), None)
    assert data == before


def test_cpu_pct_from_tick_delta() -> None:
    # 2000 total ticks elapsed, 1200 idle → 40% busy.
    assert cpu_pct_from_ticks((10000, 8500), (12000, 9700)) == 40.0
    assert cpu_pct_from_ticks(None, (1, 1)) is None
    assert cpu_pct_from_ticks((5, 5), (5, 5)) is None  # no elapsed ticks


def test_second_push_yields_cpu_pct() -> None:
    data = _payload()
    sections = parse_sections(decode_raw(data))
    _, ticks = enrich_snapshot(data, sections, None)
    later = dict(sections)
    later["kernel"] = ["1752230060", "cpu  1400 0 700 9200 600 0 0 0 0 0", "ctxt 1"]
    out, _ = enrich_snapshot(data, later, ticks)
    # delta total 1900, idle 1300 → 31.6% busy
    assert out["cpu"] == {"total_pct": 31.6}


def test_partial_output_degrades_per_section() -> None:
    data = _payload("<<<uptime>>>\n120.5 300\n<<<mem>>>\ngarbage\n")
    out, ticks = enrich_snapshot(data, parse_sections(decode_raw(data)), None)
    assert out["uptime"] == "2 mins"
    assert out["memory"] == data["memory"]  # unparseable → original kept
    assert ticks is None


def test_enriched_payload_feeds_status_converter() -> None:
    data = _payload()
    sections = parse_sections(decode_raw(data))
    out, _ = enrich_snapshot(data, sections, None)
    status = status_from_agent(out)
    assert status.memory.used_pct == out["memory"]["used_pct"]
    assert status.load.cores == 8
    assert [d.device for d in status.disks] == ["/dev/sda1", "/dev/sdb1"]
    assert status.uptime == "12 days, 8:23"


def test_uptime_formats() -> None:
    from app.agent_hub.checkmk import _parse_uptime

    assert _parse_uptime(["59.9"]) == "0 mins"
    assert _parse_uptime(["3720.0 100"]) == "1:02"
    assert _parse_uptime(["90061.5"]) == "1 days, 1:01"
    assert _parse_uptime(["-5"]) is None
    assert _parse_uptime([]) is None
