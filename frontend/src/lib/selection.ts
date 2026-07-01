// Shared client-side selection helpers — mirror of backend app/selection/model.py
// so the Settings tree and the per-instance Service Checks both resolve identically
// without re-polling. The backend stays the single source of truth; this only
// recomputes effective on/off from the rule list a /config call already returns.

import type { SelectionRule } from "./types";

// The four consumers, in the order shown to the user (notification channels then
// the Checkmk export). ``short`` is the compact column label in the checks list.
export const SELECTION_CONSUMERS = [
  { key: "mattermost", label: "Mattermost", short: "MM" },
  { key: "telegram", label: "Telegram", short: "TG" },
  { key: "email", label: "Email", short: "Mail" },
  { key: "checkmk", label: "Checkmk", short: "CMK" },
] as const;

// The part before the first ":" — JS split limit truncates the array, [0] is the
// prefix. Mirrors app/selection/model.py category().
export const categoryOf = (key: string): string => key.split(":", 1)[0];

export type Resolved = { on: boolean; by: string };

// Mirror of the backend resolve(): most-specific-wins, base default OFF.
// Precedence: instance+key > instance+cat > global+key > global+cat > default.
export function resolveClient(key: string, instanceId: number, rules: SelectionRule[]): Resolved {
  const cat = categoryOf(key);
  let bestRank = 0;
  let bestMode = "";
  for (const r of rules) {
    const isInstance = r.instance_id === instanceId;
    if (!(isInstance || r.instance_id === null)) continue;
    let rank = 0;
    if (r.selector === key) rank = isInstance ? 4 : 2;
    else if (r.selector === cat) rank = isInstance ? 3 : 1;
    else continue;
    if (rank > bestRank) {
      bestRank = rank;
      bestMode = r.mode;
    }
  }
  if (bestRank === 0) return { on: false, by: "default" };
  const reason = { 4: "instance", 3: "instance_category", 2: "global", 1: "global_category" }[
    bestRank
  ]!;
  return { on: bestMode === "include", by: reason };
}

// True when an explicit per-instance rule exists for this exact key — i.e. a
// box-level override that a toggle would clear (back to inherit) rather than add.
export function hasInstanceRule(key: string, instanceId: number, rules: SelectionRule[]): boolean {
  return rules.some((r) => r.instance_id === instanceId && r.selector === key);
}
