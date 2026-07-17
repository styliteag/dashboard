defmodule Orbit.Checks.Evaluate do
  @moduledoc """
  Threshold logic: raw agent sections → [ServiceCheck]. Pure + DB-free, a
  port of checks/evaluate.py operating directly on the raw cache maps (no
  typed-converter layer — elixir maps pattern-match fine).

  Incident rules carried over verbatim (CLAUDE.md checks section):
  - NEVER emit a check for absent data — return nil on the no-data sentinels
    (swap_total_mb<=0, disk total unknown handled via fallback levels,
    cpu absent). Emitting a check on missing data crit'd fleets (c37de13).
  - CPU deliberately can NOT crit (spiky) — WARN ceiling.
  - UNKNOWN sorts below WARN (ServiceCheck.severity).

  Families here so far: memory, swap, cpu, disk. The rest (load, pf, ntp,
  gateway, ipsec, services, certs, connectivity, firmware) port next,
  alongside overlay + the export surfaces.
  """

  alias Orbit.Checks.ServiceCheck

  # Percent thresholds — identical to evaluate.py.
  @mem_warn 80.0
  @mem_crit 90.0
  @swap_warn 50.0
  @swap_crit 80.0
  @cpu_warn 95.0
  @disk_warn 80.0
  @disk_crit 90.0
  # (min_gb, warn, crit) largest-first; disk levels scale with volume size.
  @disk_size_levels [{1024.0, 93.0, 97.0}, {200.0, 90.0, 95.0}, {50.0, 85.0, 93.0}]

  @doc """
  Evaluate every family from a raw cache `status`/section map and return the
  non-nil checks. `sections` is the hub cache entry (raw agent sections).
  """
  @spec evaluate(map()) :: [ServiceCheck.t()]
  def evaluate(sections) when is_map(sections) do
    status = sections["status"] || sections

    [
      memory_check(status["memory"]),
      swap_check(status["memory"]),
      cpu_check(status["cpu"])
    ]
    |> Enum.concat(disk_checks(status["disks"] || []))
    |> Enum.reject(&is_nil/1)
  end

  @doc "Memory used-% check. nil when no memory section."
  def memory_check(nil), do: nil

  def memory_check(%{"used_pct" => pct}) when is_number(pct) do
    {state, word} = level(pct, @mem_warn, @mem_crit)

    %ServiceCheck{
      key: "memory",
      state: state,
      summary: "Memory #{round(pct)}% used (#{word})",
      metrics: [
        ServiceCheck.metric("mem_used_pct", pct, warn: @mem_warn, crit: @mem_crit, unit: "%")
      ]
    }
  end

  def memory_check(_), do: nil

  @doc "Swap-in-use check. nil when the box reports no swap device (no data)."
  def swap_check(%{"swap_total_mb" => total, "swap_used_pct" => pct})
      when is_number(total) and total > 0 and is_number(pct) do
    {state, word} = level(pct, @swap_warn, @swap_crit)

    %ServiceCheck{
      key: "swap",
      state: state,
      summary: "Swap #{round(pct)}% used (#{word})",
      metrics: [
        ServiceCheck.metric("swap_used_pct", pct, warn: @swap_warn, crit: @swap_crit, unit: "%")
      ]
    }
  end

  def swap_check(_), do: nil

  @doc "CPU check. nil when no cpu section. CPU can WARN but NEVER crit (spiky)."
  def cpu_check(%{"total_pct" => pct}) when is_number(pct) do
    state = if pct >= @cpu_warn, do: ServiceCheck.warn(), else: ServiceCheck.ok()

    %ServiceCheck{
      key: "cpu",
      state: state,
      summary: "CPU #{round(pct)}%",
      metrics: [ServiceCheck.metric("cpu_used_pct", pct, warn: @cpu_warn, unit: "%")]
    }
  end

  def cpu_check(_), do: nil

  @doc "One check per mounted volume; levels scale with volume size."
  def disk_checks(disks) when is_list(disks) do
    for d <- disks, is_number(d["used_pct"]) do
      label = d["mountpoint"] || d["device"] || "?"
      pct = d["used_pct"]
      {warn, crit} = disk_levels(d["total_mb"])
      {state, word} = level(pct, warn, crit)
      free = free_text(d["total_mb"], pct)

      %ServiceCheck{
        key: "disk:#{label}",
        state: state,
        summary: "Disk #{label} #{round(pct)}% used (#{word}#{free})",
        metrics: [ServiceCheck.metric("disk_used_pct", pct, warn: warn, crit: crit, unit: "%")]
      }
    end
  end

  # (warn, crit) used-% levels for a volume of the given size.
  defp disk_levels(total_mb) when is_number(total_mb) and total_mb > 0 do
    gb = total_mb / 1024.0

    Enum.find_value(@disk_size_levels, {@disk_warn, @disk_crit}, fn {min_gb, warn, crit} ->
      if gb >= min_gb, do: {warn, crit}
    end)
  end

  defp disk_levels(_), do: {@disk_warn, @disk_crit}

  defp free_text(total_mb, pct) when is_number(total_mb) and total_mb > 0 do
    gb_free = total_mb * (100.0 - pct) / 100.0 / 1024.0
    ", #{:erlang.float_to_binary(gb_free, decimals: 1)} GB free"
  end

  defp free_text(_, _), do: ""

  defp level(pct, warn, crit) do
    cond do
      pct >= crit -> {ServiceCheck.crit(), "critical"}
      pct >= warn -> {ServiceCheck.warn(), "high"}
      true -> {ServiceCheck.ok(), "ok"}
    end
  end
end
