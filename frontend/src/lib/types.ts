/**
 * Shared frontend types mirroring the backend Pydantic schemas.
 * Update both sides together when the API contract changes.
 */

export interface Instance {
  id: number;
  name: string;
  base_url: string;
  ssl_verify: boolean;
  gui_login_enabled: boolean;
  agent_mode: boolean;
  device_type: string;
  transport: string;
  poll_interval_seconds: number | null;
  push_interval_seconds: number | null;
  ssh_enabled: boolean;
  ssh_port: number;
  ssh_user: string;
  ssh_key_set: boolean;
  ssh_host_key_pinned: boolean;
  agent_last_seen: string | null;
  location: string | null;
  notes: string | null;
  tags: string[] | null;
  last_success_at: string | null;
  last_error_at: string | null;
  last_error_message: string | null;
  created_at: string;
  updated_at: string;
}

/** Selectable device types for the add-instance form. */
export const DEVICE_TYPES = [
  { value: "opnsense", label: "OPNsense" },
  { value: "pfsense", label: "pfSense" },
  { value: "securepoint", label: "Securepoint UTM" },
] as const;

export interface Overview {
  total: number;
  online: number;
  degraded: number;
  offline: number;
}

export interface ConnectedAgent {
  instance_id: number;
  instance_name: string;
  agent_version: string;
  served_version: string | null;
  update_available: boolean;
  platform: string;
  last_update_error?: string | null;
  last_update_version?: string | null;
}

export interface TestConnectionResult {
  ok: boolean;
  status_code: number | null;
  latency_ms: number | null;
  error: string | null;
}

// ----- System status -------------------------------------------------------

export interface CpuStatus {
  total: number;
  user?: number;
  system?: number;
  idle?: number;
}

export interface MemoryStatus {
  total_mb: number;
  used_mb: number;
  used_pct: number;
  swap_total_mb: number;
  swap_used_mb: number;
  swap_used_pct: number;
}

export interface DiskStatus {
  mountpoint: string;
  total_mb: number;
  used_mb: number;
  used_pct: number;
}

export interface InterfaceStatus {
  name: string;
  status: string;
  address: string | null;
  bytes_received: number;
  bytes_transmitted: number;
  in_errors: number;
  out_errors: number;
  collisions: number;
}

export interface LoadAvg {
  one: number;
  five: number;
  fifteen: number;
}

export interface PfStatus {
  states_current: number;
  states_limit: number; // 0 = no data
  states_pct: number;
}

export interface NtpStatus {
  synced: boolean;
  stratum: number; // -1 = no data, 16 = reachable but unsynced
  offset_ms: number;
  jitter_ms: number;
  peer: string;
}

export interface SystemStatus {
  cpu: CpuStatus;
  memory: MemoryStatus;
  load: LoadAvg;
  pf: PfStatus;
  ntp: NtpStatus;
  disks: DiskStatus[];
  interfaces: InterfaceStatus[];
  uptime: string | null;
  version: string | null;
}

export interface ServiceInfo {
  name: string;
  description: string;
  running: boolean;
}

// ----- Metrics --------------------------------------------------------------

export interface MetricPoint {
  ts: string;
  value: number;
}

export interface MetricResponse {
  metric: string;
  range: string;
  points: MetricPoint[];
}

// ----- IPsec ---------------------------------------------------------------

export type PingState = "none" | "ok" | "fail" | "error";

export interface IPsecChild {
  name: string; // child SA name (Phase-2 id)
  local_ts: string; // local traffic selector, e.g. "10.1.1.0/24"
  remote_ts: string; // remote traffic selector, e.g. "10.2.2.0/24"
  state: string; // INSTALLED / REKEYING / "" (configured but down)
  bytes_in: number;
  bytes_out: number;
  spi_in?: string; // ESP SPIs (shared across ends) — for tunnel pairing
  spi_out?: string;
  suggested_source: string; // agent-suggested local source IP for the ping
  ping_state: PingState | string; // none | ok | fail | error
  ping_rtt_ms: number | null;
  ping_loss_pct: number | null;
  ping_ts: string | null;
}

export interface IPsecTunnel {
  id: string; // connection name — used to Connect (initiate)
  description: string;
  remote: string;
  local: string;
  phase1_status: string;
  phase2_up: number; // installed child (phase-2) SAs
  phase2_total: number; // configured child (phase-2) SAs
  seconds_established: number; // phase-1 uptime in seconds
  bytes_in: number;
  bytes_out: number;
  unique_id: string; // active IKE_SA id — used to Disconnect (terminate); empty when down
  children: IPsecChild[]; // per-Phase-2 detail (agent mode)
}

export interface IPsecPingMonitor {
  id: number;
  instance_id: number;
  tunnel_id: string;
  child_name: string;
  local_ts: string;
  remote_ts: string;
  description: string;
  source: string;
  destination: string;
  enabled: boolean;
  ping_count: number;
}

// Create/update payloads for ping monitors (PATCH is partial → all optional).
export type PingMonitorCreate = Omit<IPsecPingMonitor, "id" | "instance_id">;
export type PingMonitorUpdate = Partial<PingMonitorCreate>;

export interface PingTestResult {
  ok: boolean;
  ping_state: PingState | string; // ok | fail | error
  ping_rtt_ms: number | null;
  ping_loss_pct: number | null;
  message: string;
}

export interface IPsecServiceStatus {
  running: boolean;
  tunnels: IPsecTunnel[];
}

export interface DiagnosisSection {
  title: string;
  content: string;
}

export interface IPsecDiagnosis {
  tunnel_id: string;
  sections: DiagnosisSection[];
}

// Recorded tunnel state transition (history popup). event_type is one of
// phase1_up | phase1_down | phase1_changed | phase2_changed | ping_ok | ping_fail.
export interface IPsecTunnelEvent {
  ts: string; // ISO timestamp
  tunnel_id: string;
  child_name: string; // "" for tunnel-level events
  event_type: string;
  old_value: string;
  new_value: string;
}

export interface TunnelActionResponse {
  success: boolean;
  message: string;
}

export interface ActionResult {
  success: boolean;
  message: string;
}

// ----- Firmware -----------------------------------------------------------

export interface FirmwarePackage {
  name: string;
  current?: string | null;
  new?: string | null;
}

export interface FirmwareStatus {
  product_version: string;
  branch?: string; // pfSense update branch / software train (e.g. "26.03")
  known_branches?: string[];
  product_latest: string;
  upgrade_available: boolean;
  updates_available: number;
  status_msg: string;
  needs_reboot: boolean;
  last_check: string;
  packages: FirmwarePackage[];
}

export interface FirmwareUpgradeStatus {
  status: string;
  log: string[];
}

// --- Settings: API keys -----------------------------------------------------

export interface ApiKey {
  id: number;
  name: string;
  prefix: string;
  revealable: boolean;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ApiKeyCreated {
  id: number;
  name: string;
  prefix: string;
  key: string; // full token — shown once
}

export interface ApiKeyRevealed {
  id: number;
  key: string;
}

// --- Settings: Checkmk export config ----------------------------------------

export interface CheckmkCategoryState {
  key: string;
  excluded: boolean;
}

export interface CheckmkExclusionRule {
  id: number;
  instance_id: number | null;
  target: string;
}

export interface CheckmkConfig {
  categories: CheckmkCategoryState[];
  rules: CheckmkExclusionRule[];
}

export interface CheckmkPreviewCheck {
  key: string;
  category: string;
  state: number;
  summary: string;
  excluded: boolean;
  excluded_by: "category" | "specific" | null;
}

export interface CheckmkPreviewInstance {
  instance_id: number;
  name: string;
  device_type: string;
  checks: CheckmkPreviewCheck[];
}

export interface CheckmkPreview {
  instances: CheckmkPreviewInstance[];
}

// ----- Alerts / Service Checks (global) ------------------------------------

export interface PerfMetric {
  name: string;
  value: number;
  warn: number | null;
  crit: number | null;
  unit: string;
}

export interface ServiceAlert {
  instance_id: number;
  instance_name: string;
  key: string;
  state: number; // 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN
  summary: string;
  metrics: PerfMetric[];
  excluded: boolean;
  excluded_by: "category" | "specific" | null;
}

// --- Settings: editable application settings ---------------------------------

export interface AppSettingItem {
  key: string;
  label: string;
  group: string;
  type: "int" | "str" | "bool";
  help: string;
  value: string;
  default: string;
  source: "db" | "env";
  restart_required: boolean;
  is_secret: boolean;
  options: string[] | null;
  min: number | null;
  max: number | null;
}

export interface NotificationTestResult {
  channel: string;
  status: "sent" | "skipped" | "failed";
  detail: string;
}
