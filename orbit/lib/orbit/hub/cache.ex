defmodule Orbit.Hub.Cache do
  @moduledoc """
  Per-instance cache of the latest agent-push sections — the guarded-write
  core of hub.py `_handle_metrics`, as pure functions over a plain map so
  every guard is unit-testable. The Hub GenServer owns the state.

  Two guard kinds, mirrored 1:1 from the python hub (incident: one failed
  collector erased known-good state and fired alert pairs):

  - **truthy-guard** — empty/missing section = collector failure, keep the
    previous value: `gateways`, `ipsec`, `services`, `certificates`,
    `firmware`, `external_ip` (any-address-present), `pf_top`.
  - **presence-guard** — empty is legitimate (nothing configured), cache
    whenever the key is present: `connectivity`, `firewall_log`.
  - always: the raw snapshot status sections (`system/cpu/memory/...`) via
    `status`, and `last_metrics_ts`.

  Sections are cached RAW here; the typed converters + check evaluation
  port with M4. This cache is in-memory only — `instances.status_snapshot`
  stays python-hub property until the cutover, because both hubs share the
  column and the formats must not fight.
  """

  @type t :: %{optional(integer()) => map()}

  @truthy_sections ~w(gateways ipsec services certificates firmware pf_top)
  @presence_sections ~w(connectivity firewall_log)
  # Vendor/extension passthrough: any pushed section whose key starts with
  # `x_` is stored verbatim (truthy-guarded like the real sections). This is
  # the backend half of the agent drop-in mechanism (§28) — a downstream
  # build adds a collector as an agent/src/linux.d part that pushes e.g.
  # `x_zfs`, and it lands here + in the status_snapshot with no core change.
  # Core sections are never named `x_*`, so the namespace can't collide.
  @extra_section_prefix "x_"
  # Always-overwrite portions of the push that make up the live status view.
  # `config` = the box's last config revision (collect_config) — pushed on
  # every cycle like the other status sections, shown on the detail page.
  @status_sections ~w(ts system uptime loadavg cpu memory disks pf ntp interfaces collect_ms section_ms config)

  @doc "Apply one metrics push to the cache map; returns the updated cache."
  @spec ingest(t(), integer(), map(), DateTime.t()) :: t()
  def ingest(cache, instance_id, data, now, cpu_state \\ :unchanged) when is_map(data) do
    prev = Map.get(cache, instance_id, %{})

    entry =
      prev
      |> put_status(with_iface_rates(prev, data, now), now)
      |> apply_truthy_guards(data)
      |> apply_presence_guards(data)
      |> apply_extra_sections(data)
      |> apply_checkmk_output(data)
      |> put_external_ip(data)
      |> put_cpu_state(cpu_state)

    Map.put(cache, instance_id, entry)
  end

  @doc """
  Expand a Linux node's `checkmk_raw` blob into the normal section shapes.

  A generic Linux server ships one gzipped Checkmk-agent dump instead of the
  per-section numbers a firewall agent collects itself (§25/DR-10). This runs
  ONCE per push, before the caller feeds both the cache and the metric-history
  writer — expanding inside `ingest/5` alone left the metric series reading
  the raw push, so the charts stayed flat while the status view was correct.

  The agent also sends its own zero-filled cpu/memory/loadavg on such a box
  (its FreeBSD collectors find nothing on Linux), so the parsed values must
  WIN over what the push carried; taking the push's zeros was exactly the
  symptom — a healthy Linux node reading 0 % CPU and 0 % RAM forever.

  Returns `{data, cpu_state}`; `cpu_state` is `:unchanged` for every
  non-Linux push so `ingest/5` leaves the stored baseline alone.
  """
  @spec expand(t(), integer(), map()) :: {map(), map() | nil | :unchanged}
  def expand(cache, instance_id, data) when is_map(data) do
    case data["checkmk_raw"] do
      raw when is_map(raw) and map_size(raw) > 0 ->
        prev = Map.get(cache, instance_id, %{})
        {parsed, cpu_state} = Orbit.Hub.Checkmk.parse(raw, prev["checkmk_cpu"])
        data = Map.merge(data, parsed)

        data =
          case Orbit.Hub.Checkmk.raw_text(raw) do
            text when is_binary(text) -> Map.put(data, "checkmk_output", text)
            _ -> data
          end

        {data, cpu_state}

      _ ->
        {data, :unchanged}
    end
  end

  # Retain the raw Checkmk-agent dump for the instance's Checkmk view. Truthy-
  # guard: a push without checkmk_raw must not wipe it. In-memory only — the
  # persist path strips it (it is large, and it refreshes on the next push).
  defp apply_checkmk_output(entry, %{"checkmk_output" => text})
       when is_binary(text) and text != "",
       do: Map.put(entry, "checkmk_output", text)

  defp apply_checkmk_output(entry, _data), do: entry

  defp put_cpu_state(entry, :unchanged), do: entry
  defp put_cpu_state(entry, nil), do: entry
  defp put_cpu_state(entry, state), do: Map.put(entry, "checkmk_cpu", state)

  @doc "The cached entry for an instance (or empty map)."
  @spec entry(t(), integer()) :: map()
  def entry(cache, instance_id), do: Map.get(cache, instance_id, %{})

  @doc """
  Merge fresh fields into ONE cached section — the operator-initiated
  firmware.check verdict path (python hub.set_firmware). This is a deliberate
  targeted write outside the push-ingest guards: keys the command reported
  win, keys it didn't report keep their cached (agent-pushed) value, so a
  manual check never blanks e.g. `security_updates` from the last push.
  """
  @spec merge_section(t(), integer(), String.t(), map()) :: t()
  def merge_section(cache, instance_id, section, fields) when is_map(fields) do
    entry = entry(cache, instance_id)
    merged = Map.merge(entry[section] || %{}, fields)
    Map.put(cache, instance_id, Map.put(entry, section, merged))
  end

  @doc "Drop an instance's cache (uninstall/delete)."
  @spec drop(t(), integer()) :: t()
  def drop(cache, instance_id), do: Map.delete(cache, instance_id)

  @doc """
  Per-interface throughput, derived from the byte counters.

  The counters are cumulative, so a rate needs two pushes: this diffs each
  interface against its own previous value over the elapsed time. Without it
  `rx_rate`/`tx_rate` were never produced at all and the Network tab's RX/s
  and TX/s columns showed "—" forever, on every transport.

  A counter that went backwards (interface reset, agent restart, box reboot)
  yields no rate rather than a negative or a huge spike, and the very first
  push after a restart reports none — same honesty rule as the CPU delta.

  Gaps longer than `@max_rate_window` yield nothing either: the cache is
  rehydrated from a persisted snapshot at boot, so the first push after a
  long outage would otherwise average the whole downtime and label it as
  current throughput.
  """
  # 15 min — comfortably above 4× the longest normal push interval.
  @max_rate_window 900

  def with_iface_rates(prev, data, now) do
    ifaces = data["interfaces"]

    with true <- is_list(ifaces),
         %DateTime{} = prev_ts <- prev["last_metrics_ts"],
         seconds when seconds > 0 and seconds <= @max_rate_window <-
           DateTime.diff(now, prev_ts) do
      previous =
        prev
        |> get_in(["status", "interfaces"])
        |> List.wrap()
        |> Map.new(fn i -> {i["name"], i} end)

      Map.put(data, "interfaces", Enum.map(ifaces, &rate_for(&1, previous, seconds)))
    else
      _ -> data
    end
  end

  defp rate_for(iface, previous, seconds) do
    old = Map.get(previous, iface["name"], %{})

    iface
    |> put_rate("rx_rate", iface["bytes_received"], old["bytes_received"], seconds)
    |> put_rate("tx_rate", iface["bytes_transmitted"], old["bytes_transmitted"], seconds)
  end

  defp put_rate(iface, key, current, previous, seconds)
       when is_number(current) and is_number(previous) and current >= previous do
    Map.put(iface, key, Float.round((current - previous) / seconds, 1))
  end

  defp put_rate(iface, _key, _current, _previous, _seconds), do: iface

  defp put_status(entry, data, now) do
    status = Map.take(data, @status_sections)

    entry
    |> Map.put("status", status)
    |> Map.put("last_metrics_ts", now)
  end

  defp apply_truthy_guards(entry, data) do
    Enum.reduce(@truthy_sections, entry, fn section, acc ->
      case data[section] do
        value when value in [nil, [], %{}, ""] -> acc
        value -> Map.put(acc, section, value)
      end
    end)
  end

  # Store every `x_*` section verbatim, truthy-guarded (an empty push must not
  # wipe a known-good vendor section — same rule as the truthy sections).
  defp apply_extra_sections(entry, data) do
    Enum.reduce(data, entry, fn
      {<<@extra_section_prefix, _::binary>> = key, value}, acc
      when value not in [nil, [], %{}, ""] ->
        Map.put(acc, key, value)

      _pair, acc ->
        acc
    end)
  end

  defp apply_presence_guards(entry, data) do
    Enum.reduce(@presence_sections, entry, fn section, acc ->
      case Map.fetch(data, section) do
        {:ok, value} when not is_nil(value) -> Map.put(acc, section, value)
        _ -> acc
      end
    end)
  end

  # external_ip: truthy-guard on "any address present" — an all-empty section
  # means both ipify probes failed this cycle; keep the last known IP rather
  # than blank the NAT signal (hub.py:597-601).
  defp put_external_ip(entry, data) do
    case data["external_ip"] do
      %{} = ext ->
        if truthy(ext["ipv4"]) or truthy(ext["ipv6"]) do
          Map.put(entry, "external_ip", ext)
        else
          entry
        end

      _ ->
        entry
    end
  end

  defp truthy(value), do: value not in [nil, ""]
end
