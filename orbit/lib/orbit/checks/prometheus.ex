defmodule Orbit.Checks.Prometheus do
  @moduledoc """
  Prometheus text exposition (format 0.0.4) of evaluated checks — port of
  checks/prometheus.py. Unlike Checkmk there is no selection filtering and no
  aggregation: every evaluated check becomes a series, consumers filter in
  PromQL. `state` keeps the Checkmk convention (0/1/2/3) so both exports read
  the same.

  Labels use instance_id/instance_name, NEVER the reserved `instance`
  (Prometheus renames it to exported_instance — CLAUDE.md rule 20). Every
  emitted family must be registered in @help or strict parsers break.
  """

  @content_type "text/plain; version=0.0.4; charset=utf-8"
  def content_type, do: @content_type

  # Family → HELP text. Emission order is fixed; empty families are skipped.
  @help [
    {"orbit_instance_info", "Instance metadata; value is always 1"},
    {"orbit_check_state", "Evaluated check state: 0=OK, 1=WARN, 2=CRIT, 3=UNKNOWN"},
    {"orbit_check_metric", "Performance value of an evaluated check"},
    {"orbit_check_metric_warn", "WARN threshold of the corresponding orbit_check_metric"},
    {"orbit_check_metric_crit", "CRIT threshold of the corresponding orbit_check_metric"}
  ]

  @doc """
  Render `{instance, checks}` pairs as Prometheus text. `instance` is a map or
  struct with :id, :name, :device_type and a :mode ("push"|"poll").
  """
  @spec render([{map(), [Orbit.Checks.ServiceCheck.t()]}]) :: String.t()
  def render(rows) do
    families = Enum.reduce(rows, empty_families(), &collect_instance/2)

    lines =
      Enum.flat_map(@help, fn {name, help} ->
        case Enum.reverse(families[name]) do
          [] -> []
          samples -> ["# HELP #{name} #{help}", "# TYPE #{name} gauge" | samples]
        end
      end)

    case lines do
      [] -> ""
      _ -> Enum.join(lines, "\n") <> "\n"
    end
  end

  defp empty_families, do: Map.new(@help, fn {name, _} -> {name, []} end)

  defp collect_instance({inst, checks}, families) do
    base = [{"instance_id", to_string(inst.id)}, {"instance_name", inst.name}]

    info_labels =
      base ++ [{"device_type", inst.device_type || ""}, {"mode", inst.mode}]

    families =
      push(families, "orbit_instance_info", sample("orbit_instance_info", info_labels, 1))

    Enum.reduce(checks, families, fn check, fams ->
      key_labels = base ++ [{"key", check.key}]
      fams = push(fams, "orbit_check_state", sample("orbit_check_state", key_labels, check.state))

      Enum.reduce(check.metrics, fams, fn m, fs ->
        labels = key_labels ++ [{"metric", m.name}, {"unit", m.unit}]

        fs = push(fs, "orbit_check_metric", sample("orbit_check_metric", labels, m.value))
        fs = maybe(fs, "orbit_check_metric_warn", labels, m.warn)
        maybe(fs, "orbit_check_metric_crit", labels, m.crit)
      end)
    end)
  end

  defp maybe(families, _name, _labels, nil), do: families

  defp maybe(families, name, labels, value),
    do: push(families, name, sample(name, labels, value))

  defp push(families, name, line), do: Map.update!(families, name, &[line | &1])

  defp sample(name, labels, value) do
    inner = labels |> Enum.map(fn {k, v} -> ~s(#{k}="#{escape(v)}") end) |> Enum.join(",")
    "#{name}{#{inner}} #{fmt(value)}"
  end

  defp escape(value) do
    value
    |> to_string()
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
    |> String.replace("\n", "\\n")
  end

  # Integral floats drop the ".0"; never scientific notation (uptime seconds,
  # byte totals). Mirror of python _fmt.
  defp fmt(value) when is_integer(value), do: Integer.to_string(value)

  defp fmt(value) when is_float(value) do
    if value == Float.round(value) and abs(value) < 1.0e15 do
      value |> trunc() |> Integer.to_string()
    else
      Float.to_string(value)
    end
  end
end
