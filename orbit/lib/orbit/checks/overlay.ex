defmodule Orbit.Checks.Overlay do
  @moduledoc """
  Compose the per-instance check overlays in one place — port of
  checks/overlay.py. The raw evaluate/1 output is layered with, in order:

  1. agent-staleness — prepend the `agent` service (OK fresh / WARN stale) and
     cap stale sub-states CRIT→WARN (a "down" verdict on stale data is a guess);
  2. the out-of-band probe (ping/http) — appended after the staleness cap (the
     probe is live, and is the signal that can take a stale-but-confirmed-down
     box to CRIT, so it must not itself be capped);
  3. maintenance ceiling — cap everything at WARN + a `maintenance` banner.

  Used by every check surface (Checkmk export, Prometheus, Alerts, per-instance
  checks) so all four show identical services. Never mutates input checks —
  capped checks are new structs.
  """

  alias Orbit.Checks.Confidence
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Checks.Staleness

  @doc """
  Layer staleness + maintenance onto raw checks. `staleness` is the resolved
  `Staleness.t()` or nil; `maintenance?` the instance flag.
  """
  @spec overlay([ServiceCheck.t()], Staleness.t() | nil, boolean()) :: [ServiceCheck.t()]
  def overlay(base, staleness, maintenance?), do: overlay(base, staleness, maintenance?, nil)

  @doc """
  As `overlay/3`, plus the probe result for this instance.

  The probe is appended AFTER the staleness cap on purpose: it is freshly
  measured, so capping it would throw away the only evidence that distinguishes
  "stale and dead" from "stale but alive".
  """
  @spec overlay([ServiceCheck.t()], Staleness.t() | nil, boolean(), Orbit.Probe.result() | nil) ::
          [ServiceCheck.t()]
  def overlay(base, staleness, maintenance?, probe) do
    agent_fresh? = staleness != nil and not staleness.stale

    base
    |> apply_staleness(staleness)
    |> Kernel.++(Confidence.probe_checks(agent_fresh?, probe))
    |> apply_maintenance(maintenance?)
  end

  @doc "Prepend the `agent` service; while stale cap CRIT→WARN on the rest."
  def apply_staleness(checks, nil), do: checks

  def apply_staleness(checks, %Staleness{} = s) do
    agent = agent_check(s)

    if s.stale do
      [agent | Enum.map(checks, &cap_stale(&1, s))]
    else
      [agent | checks]
    end
  end

  @doc "Prepend the `maintenance` banner; cap every check at WARN. No-op when off."
  def apply_maintenance(checks, false), do: checks

  def apply_maintenance(checks, true) do
    banner = %ServiceCheck{
      key: "maintenance",
      state: ServiceCheck.warn(),
      summary: "In maintenance — alerts capped at WARN"
    }

    [banner | Enum.map(checks, &cap_maintenance/1)]
  end

  defp agent_check(%Staleness{stale: true} = s) do
    %ServiceCheck{
      key: "agent",
      state: ServiceCheck.warn(),
      summary: "Agent silent for #{s.age_seconds}s (>#{s.threshold}s) — sub-state data is stale"
    }
  end

  defp agent_check(%Staleness{} = s) do
    %ServiceCheck{
      key: "agent",
      state: ServiceCheck.ok(),
      summary: "Agent reporting (#{s.age_seconds}s ago)"
    }
  end

  # CRIT→WARN while stale (a down verdict on stale data is a guess); OK/WARN kept.
  defp cap_stale(%ServiceCheck{state: 2} = c, s) do
    %{
      c
      | state: ServiceCheck.warn(),
        summary: "#{c.summary} (stale: agent silent #{s.age_seconds}s)"
    }
  end

  defp cap_stale(c, _s), do: c

  # Everything above WARN capped to WARN while in maintenance.
  defp cap_maintenance(%ServiceCheck{state: state} = c) when state > 1 do
    %{c | state: ServiceCheck.warn(), summary: "#{c.summary} (maintenance)"}
  end

  defp cap_maintenance(c), do: c
end
