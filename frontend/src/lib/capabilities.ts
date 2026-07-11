/**
 * Central device-capability map (DR-8, docs/agent-architecture.md §25).
 *
 * One row per device_type — every surface that gates on the device *class*
 * (tabs, action buttons, form fields) reads from here instead of scattering
 * `device_type === "..."` checks around the codebase.
 *
 * Mirrors backend/src/app/devices/capabilities.py — update both together.
 */

export interface DeviceCaps {
  /** Orbit agent can be enrolled (push transport, Agent tab, capture, connectivity). */
  agent: boolean;
  /** IPsec/VPN surfaces apply (VPN tab). */
  tunnels: boolean;
  /** Firewall rule editor (OPNsense core API only). */
  firewallRules: boolean;
  /** The box has a web UI (GUI proxy / "Open GUI" button). */
  webif: boolean;
  /** Packet capture via the agent. */
  capture: boolean;
  /** Standalone ping monitors via the agent. */
  connectivity: boolean;
  /** SSH enrichment without an agent: shell fallback + IPsec status (Securepoint). */
  sshEnrichment: boolean;
  /** Dashboard can reach an HTTP API on the box (test connection, base_url field). */
  directApi: boolean;
  /** The box has a versioned config backup (config.xml — Config tab + download). */
  configBackup: boolean;
  /** pf filter log exists (Log tab's firewall-log block). */
  firewallLog: boolean;
  /** Label of the update surface ("Firmware" for appliances). */
  updatesLabel: "Firmware" | "Updates";
}

const FIREWALL_DEFAULTS: DeviceCaps = {
  agent: true,
  tunnels: true,
  firewallRules: false,
  webif: true,
  capture: true,
  connectivity: true,
  sshEnrichment: false,
  directApi: true,
  configBackup: true,
  firewallLog: true,
  updatesLabel: "Firmware",
};

export const DEVICE_CAPS: Record<string, DeviceCaps> = {
  opnsense: { ...FIREWALL_DEFAULTS, firewallRules: true },
  pfsense: { ...FIREWALL_DEFAULTS },
  proxmox: { ...FIREWALL_DEFAULTS },
  truenas: { ...FIREWALL_DEFAULTS },
  qnap: { ...FIREWALL_DEFAULTS },
  // Securepoint is direct-only (no agent); shell + IPsec status come via SSH enrichment.
  securepoint: {
    ...FIREWALL_DEFAULTS,
    agent: false,
    capture: false,
    connectivity: false,
    sshEnrichment: true,
  },
  // Generic Linux server (DR-9): push-only, no web UI/tunnels/rule editor.
  linux: {
    ...FIREWALL_DEFAULTS,
    tunnels: false,
    webif: false,
    directApi: false,
    configBackup: false,
    firewallLog: false,
    updatesLabel: "Updates",
  },
};

/** Caps for a device_type; unknown values fall back to the firewall defaults. */
export const deviceCaps = (deviceType?: string): DeviceCaps =>
  DEVICE_CAPS[deviceType ?? ""] ?? FIREWALL_DEFAULTS;
