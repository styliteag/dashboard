/**
 * Shared frontend types mirroring the backend Pydantic schemas.
 * Update both sides together when the API contract changes.
 */

export interface Instance {
  id: number;
  name: string;
  base_url: string;
  ssl_verify: boolean;
  agent_mode: boolean;
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

export interface Overview {
  total: number;
  online: number;
  degraded: number;
  offline: number;
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
}

export interface SystemStatus {
  cpu: CpuStatus;
  memory: MemoryStatus;
  disks: DiskStatus[];
  interfaces: InterfaceStatus[];
  uptime: string | null;
  version: string | null;
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

export interface IPsecTunnel {
  id: string;
  description: string;
  remote: string;
  local: string;
  phase1_status: string;
  bytes_in: number;
  bytes_out: number;
}

export interface IPsecServiceStatus {
  running: boolean;
  tunnels: IPsecTunnel[];
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
