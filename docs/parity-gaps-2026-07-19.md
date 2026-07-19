# Own-verified C gaps (grep-proven)

## Direct-poll (agent-less) cluster — BIGGEST
poller.ex fetch/2 (OPNsense direct) emits ONLY cpu,memory,disks,interfaces,uptime,system.
python xsense/client.py (550) also had: ipsec_status, ipsec_connect, ipsec_disconnect,
gateway_status, download_config, firewall_log.
=> direct-poll OPNsense loses: IPsec tunnels, gateways, firewall log, config backup.
Orbit.Firmware HAS direct branch + OpnsenseClient.firmware_* exist, BUT UI gates:
 - firmware_live.ex:84 Enum.filter(&agent_mode?/1)
 - instance_detail_live.ex:1576 :if={@tab=="firmware" and agent_mode?}
=> firmware context exists, UI hides it. SMALL fix, real impact. CLAIMED-CLOSED in plan header.

## Securepoint (correcting the premise)
client.ex is 322 lines at HEAD, CLEAN. Commit 55cf6f9 "derive the Securepoint metric
sections again" already restored cpu/memory/disks/interfaces/system/uptime; wired via
poller.ex:152-153 fetch_status. PREMISE WAS RIGHT WHEN WRITTEN, FIXED SINCE.
Genuine remaining: appmgmt_status (=> no services section => no service checks),
ipsec connect/disconnect/restart/diagnose, firmware_status (=> absent from compliance).
NOT losses (python neutral stubs): firmware_check/update/upgrade_status, gateway_status,
firewall_log, reboot, download_config (raised _READ_ONLY).

## Firewall rules
- /firewall/aliases (routes.py:465-510) NO orbit counterpart (grep get_aliases/aliases = 0 hits)
  => rule editor lost alias autocomplete/resolution. MEDIUM.
- /rules/{uuid}/toggle-log (routes.py:387-405) MISSING (grep toggle_log = 0). SMALL.
- /rules/options + /rules/template: orbit hardcodes new-rule defaults (firewall_rules_live.ex:109-124)
  and derives edit options from get_rule => net/port fields are free-text <input>. PARTIAL.

## VPN
- Per-instance VPN tab lost TunnelHistoryDialog + TunnelGraphDialog (present in IPsecSection.tsx:36-37,
  438,447). instance_detail_live has NO history. Only fleet vpn_live has them. MEDIUM.
- Fleet-wide aggregate graph VPNOverviewGraphDialog (208 lines) MISSING (vpn_live up_count is a
  live KPI tile only, line 451/476). MEDIUM.
- vpn_live Graph/History buttons inside <td :if={@writable}> (line 604) but python
  GET /{tunnel_id}/history = Depends(current_user) => view_only users lost read access. SMALL.

## Instances
- POST /instances/{id}/test "Test connection" MISSING (no test_connection handler in
  instance_create_live/instance_edit_live). python instances/routes.py:278. SMALL-MED.

## Config
- ConfigSection "Last backup downloaded" (last_backup_at, from audit log) MISSING
  (grep last_backup_at = 0 hits). orbit config tab has only revision_time/user/description. SMALL.

## Navigation
- /selection routed + implemented but NO link anywhere (grep ~p"/selection" outside router = 0).
  Orphaned page. SMALL.

# VERIFIED PORTED (false positives avoided)
top_talkers=>pf_top (instance_detail_live:2197 full: sources/dests/ifaces/protos/flows)
system_health => loadavg/swap/pf/ntp inline (1272-1290)
agent_runtime => collect_ms/section_ms (1079,1410) + metrics.ex:203
TunnelGraphDialog => vpn_live history_open mode: :graph (138-165)
InstanceViews => set_view list/grid (instances_live:125)
config revision => 1302-1304
nav parity complete; /apikeys linked from settings_live:413
API-key auth on exports => read_principal (user_auth.ex:213)
bulk actions full parity + direct-poll path (bulk.ex:94-118)

# DOC CONTRADICTION
plan header (elixir-liveview-rewrite.md:12-20, 2026-07-18): §14 gaps "GESCHLOSSEN"
§14 addendum (agent-architecture.md:408+, same date): many still open.
=> tag gaps: claimed-closed-but-open / known-open / unmentioned

## LLM
- DiagnoseDialog.tsx (218) had provider picker + /api/llm/preview (anonymization preview)
  + /api/llm/analyze on the IPsec diagnostic bundle => "why is this tunnel down" LLM answer.
  Orbit ipsec_diagnose (instance_detail_live:221-241) shows RAW bundle text only; no provider
  picker, no preview, no analyze. Orbit.LLM.Analyze exists (analyze_logs) but is wired ONLY to
  the Log tab ai_analyze (478). CONTEXT EXISTS, DIAGNOSE UI NOT WIRED. SMALL-MED.
- /api/llm/preview (anonymization preview) has no orbit counterpart at all.

## VERIFIED FULLY PORTED (additional)
- Settings registry: EXACT 38/38 key parity (29 static + 9 LLM provider keys).
- DB model: all 25 python __tablename__ have orbit counterparts (schemas or raw SQL +
  priv/repo/baseline_schema.sql). ZERO orphaned tables.
- MFA/auth: password change, TOTP login-enroll + verify, WebAuthn login assertion,
  passkey register + delete, mfa/methods. python SecurityPage also read-only TOTP => parity.
- Capture: snapshot + Snapshots.parse (2000 pkts) + pcap download + live WS. §14 item CLOSED.
- Agent lifecycle: refresh/reconnect/uninstall/test_api/enable/disable/show_token/update/mint_enroll.
- Relay: /relay/{path} + /relay/enable had NO react UI (API-only) => not user-visible losses.
- API-key auth on machine exports via read_principal (user_auth.ex:213).

## Connectivity monitors (asymmetric with ipsec ping monitors)
- POST /connectivity/monitors/test ("Test" before saving) MISSING. orbit has conn_create/
  conn_toggle/conn_delete only (instance_detail_live:381,392,399); Monitors has no
  test_connectivity. NOTE ipsec ping monitors DO have test (vpn_live p2mon_test). SMALL.
- PATCH /connectivity/monitors/{id} (EDIT an existing monitor) MISSING. Orbit.Monitors has
  update_ipsec (monitors.ex:179) but NO update_connectivity => must delete+recreate to change
  a target. ConnectivityMonitorDialog.tsx:74 used api.patch. SMALL-MED.

## #1 PRIORITY — Linux node metrics ingest (checkmk_raw) ENTIRELY MISSING
agent/orbit_agent.py:3005 registers ("checkmk_raw","collect_checkmk"); collect_checkmk
(2883) gzips+b64s the vendored check_mk_agent output for device_type "linux" (§25, ubn1).
python agent_hub/checkmk.py (418 lines): process_push/decode_raw/parse_sections/_parse_cpu/
_parse_kernel_ticks/cpu_pct_from_ticks/_parse_mem/_parse_df(df_v2)/_parse_lnx_if
+ piggyback handling + cumulative-jiffy CPU delta state.
ORBIT: grep checkmk_raw in lib/ => ZERO hits. hub/cache.ex:31 @status_sections has no
checkmk_raw. Payload silently DROPPED.
=> every Linux node shows NO cpu/memory/disks/interfaces and emits NO checks.
Worst failure mode: orbit STILL serves the installer (/api/agent/checkmk,
agent_api_controller) + renders linux install cmds (instance_detail_live:595,622,642),
so the box enrolls, connects, and looks healthy while producing nothing.
Host: new file orbit/lib/orbit/hub/checkmk.ex + wire into hub ingest + cache sections. LARGE.

## Access log
- API-key (orbit_) usage NOT recorded. python access/store.py:93 record_apikey wrote
  ptype="apikey" into access_stats. orbit: read_api pipeline (router.ex) has NO track_access
  plug; grep '"apikey"' in lib/ hits only an audit target_type (api_keys_live:94).
  => Checkmk/Prometheus scrapers invisible in Access log; can't tell if a key is still in
  use before purging. Known-open in §14. SMALL.

## VERIFIED PORTED (final batch)
- Access-log summary/timeline/grouped + freetext q + hours window => audit_live Access tab
  (§14 item now CLOSED).
- /api/overview KPI bucketing => instances_live KPI tiles + status_filter buckets.
- Hub stats counters, pushes, served_version, version tally => hub_status_live.
- Checkmk/Prometheus EXPORT (checks/export.ex) present incl. piggyback.

---

## Nachtrag: unabhängig nachgeprüft (2026-07-19)

Zwei Befunde habe ich nach dem Sweep selbst per grep verifiziert, nicht nur übernommen:

1. **`checkmk_raw`** — `grep -rn checkmk_raw orbit/lib/` = 0 Treffer; der Agent
   registriert die Sektion in `_SNAPSHOT_SECTIONS` (`orbit_agent.py:3005`);
   `orbit/lib/orbit/hub/cache.ex:31 @status_sections` listet sie nicht, das
   `Map.take` in Zeile 70 verwirft sie also still. Orbit serviert weiterhin den
   Installer (`router.ex:219 get "/agent/checkmk"`). Ergebnis: ein Linux-Knoten
   enrollt, verbindet sich, wirkt gesund und liefert nichts.

2. **Firmware-Gating** — `firmware_live.ex:84` filtert auf `agent_mode?`,
   `instance_detail_live.ex:1576` gated den Tab ebenso, während
   `orbit/lib/orbit/firmware.ex` in den Zeilen 45/60/79/83 einen
   funktionierenden `direct(...)`-Zweig besitzt. Fertiger Code, von der UI
   versteckt.

Status: beide OFFEN. Priorisierung durch den Maintainer: die Securepoint-Reihe
(swanctl-Parser + SSH-Enrichment) läuft zuerst, diese Punkte danach.

Nicht nachgeprüft und daher als Behauptung des Sweeps zu lesen: alle übrigen
Einträge oben sowie die "vollständig portiert"-Liste.
