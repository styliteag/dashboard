defmodule Orbit.Checks.Export do
  @moduledoc """
  Machine-export assembly for the Checkmk + Prometheus surfaces — the export
  half of checks/routes.py. Evaluates every VISIBLE instance's cached sections
  through evaluate/1 + the overlay, then shapes them.

  Scoping is the caller's (routes pass the principal to list_visible); hub
  cache is unscoped in-memory data, so the instance list is the scope gate
  (invariant 5). Push instances read the hub section cache (cheap); direct
  instances need the poller (not ported yet) — they are skipped here with a
  documented seam, so a direct instance currently exports no checks.

  Checkmk-only shaping (routes.py export_checkmk parity): the blackout
  toggle empties the export, selection rules filter per check (base default
  OFF — nothing exports until an include rule matches), and the aggregate
  toggle collapses high-fan-out families. Prometheus never filters,
  aggregates or blacks out — every evaluated check becomes a series.
  """

  alias Orbit.Checks.{Aggregate, Evaluate, Overlay, Prometheus, Staleness}
  alias Orbit.Instances.Instance

  @doc "Evaluated+overlaid `{instance, checks}` pairs for every visible instance."
  @spec evaluated(Orbit.Auth.Scope.principal(), DateTime.t()) :: [{map(), list()}]
  def evaluated(principal, now) do
    principal
    |> Orbit.Instances.list_visible()
    |> Enum.filter(&Instance.agent_mode?/1)
    |> Enum.map(fn inst -> {inst_view(inst), checks_for(inst, now)} end)
  end

  @doc """
  Evaluated+overlaid checks for a single, already-scoped agent-mode instance —
  the per-instance surface. Shares the exact evaluate→overlay chain with the
  Checkmk/Prometheus/Alerts surfaces so all four agree (the parity rule).
  """
  @spec checks_for(Instance.t(), DateTime.t()) :: list()
  def checks_for(%Instance{} = inst, now) do
    push_default = Orbit.Settings.effective("push_interval_seconds")
    stale_floor = Orbit.Settings.effective("agent_stale_seconds")

    base = inst.id |> Orbit.Hub.cache_entry() |> Evaluate.evaluate()
    staleness = Staleness.resolve(inst, push_default, stale_floor, now)
    Overlay.overlay(base, staleness, inst.maintenance == true)
  end

  @doc "Checkmk special-agent JSON body (version 1)."
  @spec checkmk(Orbit.Auth.Scope.principal(), DateTime.t()) :: map()
  def checkmk(principal, now) do
    # Maintenance blackout: return no instances so Checkmk sees every service
    # go stale/gone. Checked first — during a blackout we skip evaluating the
    # whole fleet entirely (routes.py parity).
    if Orbit.Settings.effective("checkmk_blackout") do
      %{version: 1, instances: []}
    else
      principal
      |> evaluated(now)
      |> checkmk_body(
        &Orbit.Selection.is_on_live("checkmk", &1, &2),
        Orbit.Settings.effective("checkmk_aggregate")
      )
    end
  end

  @doc """
  Pure Checkmk shaping over already-evaluated `{instance, checks}` pairs:
  selection filter (`selected?.(check_key, instance_id)`), then the optional
  aggregate collapse — after selection, so aggregates reflect exported
  checks. Split out so tests drive it without DB/persistent_term state.
  """
  @spec checkmk_body([{map(), list()}], (String.t(), integer() -> boolean()), boolean()) :: map()
  def checkmk_body(pairs, selected?, aggregate?) do
    instances =
      for {inst, checks} <- pairs do
        checks = Enum.filter(checks, &selected?.(&1.key, inst.id))
        checks = if aggregate?, do: Aggregate.aggregate_for_checkmk(checks), else: checks

        %{
          instance_id: inst.id,
          name: inst.name,
          # piggyback host name (checkmk export parity)
          host: inst.name,
          device_type: inst.device_type,
          checks: Enum.map(checks, &check_json/1)
        }
      end

    %{version: 1, instances: instances}
  end

  @doc "Prometheus text exposition."
  @spec prometheus(Orbit.Auth.Scope.principal(), DateTime.t()) :: String.t()
  def prometheus(principal, now) do
    # Per-instance families first, then the dashboard-global denial counters
    # (no instance labels — parity with the python route append).
    (principal |> evaluated(now) |> Prometheus.render()) <> Prometheus.render_geoip_denials()
  end

  # Duck-typed instance view the renderers consume (id/name/device_type/mode).
  defp inst_view(%Instance{} = i) do
    %{
      id: i.id,
      name: i.name,
      device_type: i.device_type,
      mode: if(Instance.agent_mode?(i), do: "push", else: "poll")
    }
  end

  defp check_json(c) do
    %{
      key: c.key,
      state: c.state,
      summary: c.summary,
      metrics: Enum.map(c.metrics, &metric_json/1)
    }
  end

  defp metric_json(m) do
    %{name: m.name, value: m.value, warn: m.warn, crit: m.crit, unit: m.unit}
  end
end
