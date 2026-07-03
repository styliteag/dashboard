/**
 * Shared frontend types mirroring the backend Pydantic schemas.
 * Update both sides together when the API contract changes.
 */

export interface Instance {
  id: number;
  name: string;
  /** Owning group (visibility scope); resolve the name via me.groups or /api/groups. */
  group_id: number;
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
  /** Optional out-of-band probe target (URL or host); null = no probe. */
  ping_url: string | null;
  /** Maintenance ceiling: while true, all checks cap at WARN (yellow, never red). */
  maintenance: boolean;
  /** While true, single-instance and bulk firmware updates are blocked. */
  firmware_locked: boolean;
  /** Push mode: agent silent past its threshold — last-known sub-states are stale. */
  stale: boolean;
  stale_seconds: number | null;
  created_at: string;
  updated_at: string;
}

/** Selectable device types for the add-instance form. */
export const DEVICE_TYPES = [
  { value: "opnsense", label: "OPNsense" },
  { value: "pfsense", label: "pfSense" },
  { value: "securepoint", label: "Securepoint UTM" },
] as const;

/** Proper product spelling for a device_type / agent platform value ("opnsense" → "OPNsense"). */
export const deviceTypeLabel = (value?: string): string =>
  DEVICE_TYPES.find((d) => d.value === value)?.label ?? value ?? "";

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
  // Server-derived bytes/sec (agent mode). -1 = no rate yet → fall back to
  // client-side delta.
  rx_rate: number;
  tx_rate: number;
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

export interface ConfigInfo {
  revision_time: string;
  revision_description: string;
  revision_user: string;
}

export interface SystemStatus {
  cpu: CpuStatus;
  memory: MemoryStatus;
  load: LoadAvg;
  pf: PfStatus;
  ntp: NtpStatus;
  config: ConfigInfo;
  disks: DiskStatus[];
  interfaces: InterfaceStatus[];
  uptime: string | null;
  version: string | null;
  // Agent collection runtime from the last push (push agents only). collect_ms is
  // the whole cycle; section_ms maps collector name -> milliseconds. Live snapshot,
  // not history — shown on the Agent tab.
  collect_ms?: number | null;
  section_ms?: Record<string, number>;
}

export interface ConfigInfoResponse extends ConfigInfo {
  last_backup_at: string | null;
}

export interface ServiceInfo {
  name: string;
  description: string;
  running: boolean;
}

export interface CertInfo {
  refid: string;
  name: string;
  type: string; // "cert" | "ca"
  is_gui: boolean;
  not_after: string; // ISO expiry
  days_remaining: number; // negative = expired
  subject: string;
  issuer: string;
}

export interface CheckHistoryEvent {
  ts: string;
  check_key: string;
  old_state: number; // 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN
  new_state: number;
  summary: string;
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
  dup_count?: number; // INSTALLED child SAs sharing this selector pair (>1 = duplicate Phase-2)
  phase2_dup_persistent?: boolean; // duplicate has persisted across polls — show the note
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

// ----- Connectivity (standalone, tunnel-independent ping monitors) ----------

export interface ConnectivityMonitor {
  id: number;
  instance_id: number;
  name: string;
  source: string; // local box-owned source IP; "" = default route
  destination: string;
  enabled: boolean;
  ping_count: number;
}

export type ConnMonitorCreate = Omit<ConnectivityMonitor, "id" | "instance_id">;
export type ConnMonitorUpdate = Partial<ConnMonitorCreate>;

// A monitor joined with its latest pushed ping result (GET /connectivity/status).
export interface ConnectivityState extends ConnectivityMonitor {
  ping_state: PingState | string; // none | ok | fail | error
  ping_rtt_ms: number | null;
  ping_loss_pct: number | null;
  ping_ts: string | null;
}

// Global Connectivity overview (GET /connectivity/overview) — one row per monitor
// across all instances.
export interface GlobalConnMonitor {
  instance_id: number;
  instance_name: string;
  id: number;
  name: string;
  source: string;
  destination: string;
  enabled: boolean;
  tags: string[];
  stale: boolean;
  stale_seconds: number | null;
  ping_state: PingState | string;
  ping_rtt_ms: number | null;
  ping_loss_pct: number | null;
  ping_ts: string | null;
}

export interface GlobalConnectivityResponse {
  monitors: GlobalConnMonitor[];
  total: number;
  ok: number;
  down: number;
  error: number;
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
  check_failed?: boolean; // update check could not run — verdict unknown
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
  /** Group binding — empty = global key (sees all instances). */
  groups: GroupBrief[];
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

// --- Settings: service selection (Checkmk export + notification channels) ---
// One model for every consumer ("checkmk" + the channels). Base default is OFF;
// an include rule turns a category/service on, an exclude rule mutes it.

export interface SelectionCategoryState {
  key: string;
  included: boolean; // a global include rule exists for this category
}

export interface SelectionRule {
  id: number;
  instance_id: number | null; // null = global (every instance)
  selector: string; // category token or full check key
  mode: "include" | "exclude";
}

export interface SelectionConfig {
  consumer: string;
  configured: boolean | null; // channel send-config status; null for checkmk
  categories: SelectionCategoryState[];
  rules: SelectionRule[];
}

export interface SelectionPreviewCheck {
  key: string;
  category: string;
  state: number;
  summary: string;
  on: boolean; // is this consumer interested in the check for this instance?
  by: string; // "instance" | "instance_category" | "global" | "global_category" | "default"
}

export interface SelectionPreviewInstance {
  instance_id: number;
  name: string;
  device_type: string;
  checks: SelectionPreviewCheck[];
}

export interface SelectionPreview {
  instances: SelectionPreviewInstance[];
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
  excluded: boolean; // true when the Checkmk export does not include it
  excluded_by: string | null; // selection level that decided, or null
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

export type UserRole = "admin" | "user" | "view_only";

/** Minimal group reference (embedded in /auth/me and /api/users). */
export interface GroupBrief {
  id: number;
  name: string;
}

/** Full group row from /api/groups (superadmin only). */
export interface Group {
  id: number;
  name: string;
  created_at: string;
  member_count: number;
  instance_count: number;
}

/** Instance reference inside a group (superadmin move UI; no status/config data). */
export interface GroupInstance {
  id: number;
  name: string;
  slug: string;
}

export interface DashUser {
  id: number;
  username: string;
  role: UserRole;
  is_superadmin: boolean;
  groups: GroupBrief[];
  created_at: string;
  disabled: boolean;
  totp_enabled: boolean;
}
