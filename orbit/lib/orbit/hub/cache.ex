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
  # Always-overwrite portions of the push that make up the live status view.
  # `config` = the box's last config revision (collect_config) — pushed on
  # every cycle like the other status sections, shown on the detail page.
  @status_sections ~w(ts system uptime loadavg cpu memory disks pf ntp interfaces collect_ms section_ms config)

  @doc "Apply one metrics push to the cache map; returns the updated cache."
  @spec ingest(t(), integer(), map(), DateTime.t()) :: t()
  def ingest(cache, instance_id, data, now) when is_map(data) do
    entry =
      cache
      |> Map.get(instance_id, %{})
      |> put_status(data, now)
      |> apply_truthy_guards(data)
      |> apply_presence_guards(data)
      |> put_external_ip(data)

    Map.put(cache, instance_id, entry)
  end

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
