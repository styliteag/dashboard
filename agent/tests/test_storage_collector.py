"""Tests for collect_storage — physical disk inventory + root-disk detection.

Fixture output is real `geom disk list` / `df -T /` / `zpool status -L` data
from a Netgate ARM box (pfplus1: internal 9.7G eMMC + 119G Kingston M.2 SATA,
ZFS root on ada0s3a) captured 2026-08-06.
"""

from __future__ import annotations

import orbit_agent as agent
import pytest

GEOM_DISK_LIST = """\
Geom name: flash/spi0
Providers:
1. Name: flash/spi0
   Mediasize: 4194304 (4.0M)
   Sectorsize: 4096
   Mode: r0w0e0
   descr: w25q32
   ident: (null)

Geom name: mmcsd0
Providers:
1. Name: mmcsd0
   Mediasize: 10427039744 (9.7G)
   Sectorsize: 512
   Mode: r0w0e0
   descr: MMCHC TX2932 8.10 SN 528C164D MFG 04/2022 by 112 0x0000
   ident: 528C164D

Geom name: mmcsd0boot0
Providers:
1. Name: mmcsd0boot0
   Mediasize: 4194304 (4.0M)
   Sectorsize: 512
   descr: MMCHC TX2932 8.10 SN 528C164D MFG 04/2022 by 112 0x0000
   ident: 528C164D

Geom name: mmcsd0boot1
Providers:
1. Name: mmcsd0boot1
   Mediasize: 4194304 (4.0M)
   Sectorsize: 512
   descr: MMCHC TX2932 8.10 SN 528C164D MFG 04/2022 by 112 0x0000
   ident: 528C164D

Geom name: ada0
Providers:
1. Name: ada0
   Mediasize: 128035676160 (119G)
   Sectorsize: 512
   Mode: r2w2e4
   descr: KINGSTON OM4P0S3128Q-A0
   ident: 50026B76877580ED
"""

DF_ZFS_ROOT = """\
Filesystem           Type 1K-blocks    Used    Avail Capacity  Mounted on
pfSense/ROOT/default zfs   91741772 2004232 89737540     2%    /
"""

ZPOOL_STATUS_SSD = """\
  pool: pfSense
 state: ONLINE
config:

\tNAME        STATE     READ WRITE CKSUM
\tpfSense     ONLINE       0     0     0
\t  ada0s3a   ONLINE       0     0     0

errors: No known data errors
"""

ZPOOL_STATUS_EMMC = ZPOOL_STATUS_SSD.replace("ada0s3a", "mmcsd0s2a")

DF_UFS_ROOT = """\
Filesystem   Type 1K-blocks    Used   Avail Capacity  Mounted on
/dev/da0s1a  ufs    7325950 2004232 4735722    30%    /
"""


def _fake_run(outputs: dict):
    """Dispatch _run by the command's first word; '' for anything unknown."""

    def run(cmd: list, timeout: int = 5) -> str:
        return outputs.get(cmd[0], "")

    return run


def test_zfs_root_on_ssd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent,
        "_run",
        _fake_run({"geom": GEOM_DISK_LIST, "df": DF_ZFS_ROOT, "zpool": ZPOOL_STATUS_SSD}),
    )
    out = agent.collect_storage()
    # Pseudo devices are filtered: SPI boot flash and the eMMC boot partitions.
    assert [d["name"] for d in out["disks"]] == ["mmcsd0", "ada0"]
    assert out["disks"][0]["size_bytes"] == 10427039744
    assert out["disks"][1]["size_bytes"] == 128035676160
    assert out["disks"][1]["descr"] == "KINGSTON OM4P0S3128Q-A0"
    assert out["system_disks"] == ["ada0"]


def test_zfs_root_on_emmc_longest_prefix_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """mmcsd0s2a must map to mmcsd0 even though mmcsd0boot0 shares the prefix."""
    monkeypatch.setattr(
        agent,
        "_run",
        _fake_run({"geom": GEOM_DISK_LIST, "df": DF_ZFS_ROOT, "zpool": ZPOOL_STATUS_EMMC}),
    )
    assert agent.collect_storage()["system_disks"] == ["mmcsd0"]


def test_ufs_root_device(monkeypatch: pytest.MonkeyPatch) -> None:
    geom = GEOM_DISK_LIST.replace("Geom name: ada0", "Geom name: da0").replace(
        "1. Name: ada0", "1. Name: da0"
    )
    monkeypatch.setattr(agent, "_run", _fake_run({"geom": geom, "df": DF_UFS_ROOT}))
    assert agent.collect_storage()["system_disks"] == ["da0"]


def test_no_geom_output_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """{} on a box without geom → the hub truthy-guard keeps previous state."""
    monkeypatch.setattr(agent, "_run", _fake_run({}))
    assert agent.collect_storage() == {}


def test_unknown_root_yields_empty_system_disks(monkeypatch: pytest.MonkeyPatch) -> None:
    """df failing must not drop the inventory — system_disks just stays []."""
    monkeypatch.setattr(agent, "_run", _fake_run({"geom": GEOM_DISK_LIST}))
    out = agent.collect_storage()
    assert [d["name"] for d in out["disks"]] == ["mmcsd0", "ada0"]
    assert out["system_disks"] == []


def test_storage_section_registered() -> None:
    assert ("storage", "collect_storage") in agent._SNAPSHOT_SECTIONS
