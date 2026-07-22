defmodule Orbit.Metrics do
  @moduledoc """
  Read metric time-series from the alembic-owned `metrics` table
  (metrics/store.py parity — the write side stays with the active poller
  stack until cutover).

  Metric names follow `<category>.<name>` (`cpu.total`, `memory.used_pct`,
  `iface.wan.bytes_rx`, …). Bucketing happens in MariaDB via
  `FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV n * n)` — safe only because every
  connection is UTC-pinned in `Orbit.Repo.init/2`.
  """

  # Range → {window seconds, bucket seconds}; bucket 0 = raw rows.
  # Mirror of RANGE_BUCKETS in backend/src/app/metrics/routes.py.
  @range_buckets %{
    "1h" => {3_600, 0},
    "6h" => {21_600, 60},
    "24h" => {86_400, 300},
    "7d" => {604_800, 900},
    "30d" => {2_592_000, 3_600}
  }

  @doc "Window + bucket seconds for a UI range string; unknown ranges read as 24h."
  def range_bucket(range), do: Map.get(@range_buckets, range, @range_buckets["24h"])

  @doc """
  Time-series for one instance + metric over a UI range.
  Returns `[%{ts: DateTime, value: float}]`, oldest first.
  """
  def read(instance_id, metric, range) do
    {window, bucket} = range_bucket(range)
    {sql, params} = build_query(instance_id, metric, bucket, window: window)

    Orbit.Repo.query!(sql, params).rows
    |> Enum.map(fn [ts, value] -> %{ts: as_utc(ts), value: to_float(value)} end)
  rescue
    _ -> []
  catch
    # Guarded HERE, not only in the caller: a chart with no points is always
    # a better answer than a crash, and leaving that to each caller means the
    # next one silently inherits an unguarded query. A pool checkout exits
    # rather than raising, so `rescue` alone would not have covered it.
    _kind, _reason -> []
  end

  @doc """
  The `{sql, params}` pair for a read. The bucket size is inlined as a
  literal (it is grouped on), which is safe: it comes from `@range_buckets`,
  never from user input.
  """
  def build_query(instance_id, metric, bucket_seconds, opts \\ []) do
    window = Keyword.get(opts, :window, 86_400)
    end_naive = naive_utc_now()
    start_naive = NaiveDateTime.add(end_naive, -window)
    params = [instance_id, metric, start_naive, end_naive]

    sql =
      if bucket_seconds > 0 do
        "SELECT FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV #{bucket_seconds} * #{bucket_seconds}) " <>
          "AS ts, avg(value) AS value FROM metrics " <>
          "WHERE instance_id = ? AND metric = ? AND ts >= ? AND ts <= ? " <>
          "GROUP BY 1 ORDER BY 1"
      else
        "SELECT ts, value FROM metrics " <>
          "WHERE instance_id = ? AND metric = ? AND ts >= ? AND ts <= ? ORDER BY ts"
      end

    {sql, params}
  end

  @doc """
  Fleet push activity: pushes per bucket across all instances, counted via
  the `cpu.total` rows (written exactly once per push/poll — the cheapest
  honest push counter; the react hub chart sampled client-side instead).
  """
  def push_rate(range) do
    {window, bucket} = range_bucket(range)
    bucket = max(bucket, 60)
    end_naive = naive_utc_now()
    start_naive = NaiveDateTime.add(end_naive, -window)

    Orbit.Repo.query!(
      "SELECT FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV #{bucket} * #{bucket}) AS ts, " <>
        "COUNT(*) AS value FROM metrics " <>
        "WHERE metric = 'cpu.total' AND ts >= ? AND ts <= ? GROUP BY 1 ORDER BY 1",
      [start_naive, end_naive]
    ).rows
    |> Enum.map(fn [ts, value] -> %{ts: as_utc(ts), value: to_float(value)} end)
  rescue
    _ -> []
  catch
    # A pool checkout exits rather than raising; same fallback, or a stressed
    # database takes the whole page down instead of one panel.
    _kind, _reason -> []
  end

  @doc """
  Differentiate a monotonic counter series into per-second rates (iface byte
  counters → bytes/sec). Drops the first point (no predecessor); counter
  resets (negative delta, e.g. reboot) clamp to 0.0 instead of spiking.
  """
  def to_rate(points) do
    points
    |> Enum.zip(Enum.drop(points, 1))
    |> Enum.flat_map(fn {prev, cur} ->
      dt = DateTime.diff(cur.ts, prev.ts)

      cond do
        dt <= 0 -> []
        cur.value >= prev.value -> [%{ts: cur.ts, value: (cur.value - prev.value) / dt}]
        true -> [%{ts: cur.ts, value: 0.0}]
      end
    end)
  end

  # ---- write side (metrics/store.py write_poll_metrics parity) -------------

  # The uptime string shape depends on the source: the agent relays the
  # uptime binary ("18 days, 22:03", "5 mins", "1:02"), the OPNsense direct
  # poll pre-formats "1d 18h 18m", Securepoint reports "13 days, 4:07:32".
  @uptime_units [
    {~r/(\d+)\s*(?:d\b|day)/, 86_400},
    {~r/(\d+)\s*(?:h\b|hr|hour)/, 3_600},
    {~r/(\d+)\s*(?:m\b|min)/, 60},
    {~r/(\d+)\s*(?:s\b|sec)/, 1}
  ]
  @uptime_clock ~r/\b(\d+):(\d{2})(?::(\d{2}))?\b/

  @doc """
  Parse a human uptime string into seconds; nil when unparseable — an odd
  format must never fake a 0-uptime reboot into the sawtooth series.
  """
  def uptime_to_seconds(uptime) when is_binary(uptime) and uptime != "" do
    s = uptime |> String.trim() |> String.downcase()

    unit_total =
      Enum.reduce(@uptime_units, 0, fn {pattern, mult}, acc ->
        case Regex.run(pattern, s) do
          [_, n] -> acc + String.to_integer(n) * mult
          nil -> acc
        end
      end)

    clock_total =
      case Regex.run(@uptime_clock, s) do
        [_, h, m] ->
          String.to_integer(h) * 3_600 + String.to_integer(m) * 60

        [_, h, m, sec] ->
          String.to_integer(h) * 3_600 + String.to_integer(m) * 60 + String.to_integer(sec)

        nil ->
          nil
      end

    cond do
      unit_total > 0 and clock_total != nil -> unit_total + clock_total
      unit_total > 0 -> unit_total
      clock_total != nil -> clock_total
      true -> nil
    end
  end

  def uptime_to_seconds(_), do: nil

  @doc """
  Map one raw agent push (converters.py input shape) onto `{metric, value}`
  rows. Metric names are bit-identical to the python writer — same table,
  the series must stay continuous across the cutover. No-data sentinels
  (swap_total 0, states_limit 0, absent collect_ms, unparseable uptime)
  write nothing rather than a misleading 0-series.
  """
  def rows_for_push(data) when is_map(data) do
    mem = data["memory"] || %{}
    load = data["loadavg"] || %{}
    pf = data["pf"] || %{}

    uptime_rows =
      case uptime_to_seconds(data["uptime"]) do
        nil -> []
        seconds -> [{"system.uptime_seconds", seconds * 1.0}]
      end

    swap_rows =
      if num(mem["swap_total_mb"]) > 0,
        do: [{"memory.swap_used_pct", num(mem["swap_used_pct"])}],
        else: []

    pf_rows =
      if num(pf["states_limit"]) > 0 do
        [
          {"pf.states_current", num(pf["states_current"])},
          {"pf.states_pct", num(pf["states_pct"])}
        ]
      else
        []
      end

    disk_rows =
      for d <- data["disks"] || [] do
        {"disk.#{disk_label(d["mountpoint"])}.used_pct", num(d["used_pct"])}
      end

    iface_rows =
      Enum.flat_map(data["interfaces"] || [], fn i ->
        safe = iface_label(i["name"])

        [
          {"iface.#{safe}.bytes_rx", num(i["bytes_received"])},
          {"iface.#{safe}.bytes_tx", num(i["bytes_transmitted"])}
        ]
      end)

    collect_rows =
      case data["collect_ms"] do
        nil -> []
        ms -> [{"agent.collect_ms", num(ms)}]
      end

    uptime_rows ++
      [
        {"cpu.total", num(get_in(data, ["cpu", "total_pct"]))},
        {"memory.used_pct", num(mem["used_pct"])},
        {"memory.total_mb", num(mem["total_mb"])},
        {"memory.used_mb", num(mem["used_mb"])},
        {"load.1m", num(load["one"])},
        {"load.5m", num(load["five"])},
        {"load.15m", num(load["fifteen"])}
      ] ++
      swap_rows ++ pf_rows ++ disk_rows ++ iface_rows ++ collect_rows ++ vendor_rows(data)
  end

  # Extra metric series a downstream build registers (§28). Each entry is an
  # `{module, function}` whose `fun(push)` returns `[{metric_name, value}]`;
  # they append to the fixed core series above. The `metrics` table is generic
  # (a metric-name string + a double), so this adds ROWS, never a column or a
  # table — open's and a downstream's schema stay bit-identical, and open, which
  # registers nothing here, simply never writes (or reads) those names.
  # compile_env in the module body, not per call.
  @vendor_metrics Application.compile_env(:orbit, :vendor_metrics, [])

  defp vendor_rows(data) do
    Enum.flat_map(@vendor_metrics, fn {mod, fun} ->
      # An extractor must never break the core series persist.
      try do
        mod |> apply(fun, [data]) |> List.wrap() |> Enum.filter(&metric_row?/1)
      rescue
        _ -> []
      end
    end)
  end

  defp metric_row?({name, value})
       when is_binary(name) and byte_size(name) <= 128 and is_number(value),
       do: true

  defp metric_row?(_), do: false

  @doc """
  Persist one push as metric rows (INSERT IGNORE — replays of the same
  (instance, ts, metric) are dropped by the unique key, python parity).
  """
  def write_push(instance_id, %DateTime{} = ts, data) do
    rows = rows_for_push(data)

    if rows != [] do
      naive = ts |> DateTime.to_naive() |> NaiveDateTime.truncate(:second)
      placeholders = Enum.map_join(rows, ", ", fn _ -> "(?, ?, ?, ?)" end)
      params = Enum.flat_map(rows, fn {metric, value} -> [instance_id, naive, metric, value] end)

      Orbit.Repo.query!(
        "INSERT IGNORE INTO metrics (instance_id, ts, metric, value) VALUES " <> placeholders,
        params
      )
    end

    length(rows)
  end

  # `.strip("_")` python semantics; "/" collapses to "root".
  defp disk_label(mountpoint) do
    case (mountpoint || "") |> String.replace("/", "_") |> String.trim("_") do
      "" -> "root"
      label -> label
    end
  end

  # "[LAN] vmx0" → "lan_vmx0", capped at 40 chars (python writer parity).
  defp iface_label(name) do
    (name || "")
    |> String.replace(["[", "]", "(", ")"], "")
    |> String.replace(" ", "_")
    |> String.downcase()
    |> String.slice(0, 40)
  end

  defp num(v) when is_number(v), do: v * 1.0
  defp num(_), do: 0.0

  # MariaDB DATETIME reads back naive-but-UTC — tag it before use.
  defp as_utc(%NaiveDateTime{} = naive), do: DateTime.from_naive!(naive, "Etc/UTC")
  defp as_utc(%DateTime{} = dt), do: dt

  defp naive_utc_now do
    DateTime.utc_now() |> DateTime.to_naive() |> NaiveDateTime.truncate(:second)
  end

  defp to_float(%Decimal{} = d), do: Decimal.to_float(d)
  defp to_float(v) when is_integer(v), do: v * 1.0
  defp to_float(v) when is_float(v), do: v
end
