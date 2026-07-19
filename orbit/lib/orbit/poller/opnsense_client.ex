defmodule Orbit.Poller.OpnsenseClient do
  @moduledoc """
  OPNsense/pfSense diagnostics API client (direct-poll transport) — port of
  the fetch half of xsense/client.py. Basic-auth with the instance's
  fernet-decrypted api key/secret; the parse functions produce the SAME raw
  section shapes the agent pushes (cpu.total_pct, memory.used_pct/total_mb,
  disks[].used_pct/...), so a direct-polled instance feeds the exact same
  Checks engine + cache as a push instance.

  This is the grounding slice: client construction + the systemResources /
  systemDisk fetch + their parsers. The remaining endpoints (interfaces,
  gateways, ipsec, services, certs, firmware) port alongside the poll
  scheduler that drives them.
  """

  alias Orbit.Instances.Instance

  @connect_timeout 5_000
  @recv_timeout 15_000

  defstruct [:base_url, :api_key, :api_secret, :ssl_verify]

  @doc "Build a client from an instance (decrypts the api key/secret)."
  @spec new(Instance.t()) :: {:ok, t()} | {:error, term()}
  def new(%Instance{} = inst) do
    with {:ok, key} <- Orbit.Crypto.decrypt(inst.api_key_enc),
         {:ok, secret} <- Orbit.Crypto.decrypt(inst.api_secret_enc) do
      {:ok,
       %__MODULE__{
         base_url: Instance.primary_base_url(inst) |> String.trim_trailing("/"),
         api_key: key,
         api_secret: secret,
         ssl_verify: inst.ssl_verify
       }}
    end
  end

  @type t :: %__MODULE__{}

  @doc """
  Fetch the live status of a direct-poll box as raw sections
  (%{"cpu" => ..., "memory" => ..., "disks" => [...]}), Checks-engine-ready.
  Best-effort per section: a failing endpoint yields an empty section, never
  a crash (mirrors the python per-aspect try/except).
  """
  @spec fetch_status(t()) :: map()
  def fetch_status(%__MODULE__{} = c) do
    resources = get(c, "/api/diagnostics/system/systemResources")
    disk = get(c, "/api/diagnostics/system/systemDisk")
    ifaces = get(c, "/api/diagnostics/interface/getInterfaceStatistics")
    activity = get(c, "/api/diagnostics/activity/getActivity")
    info = get(c, "/api/diagnostics/system/system_information")

    %{}
    |> put_section("cpu", cpu_from_resources(resources))
    |> put_section("memory", memory_from_resources(resources))
    |> put_section("disks", disks_from_systemdisk(disk))
    |> put_section("interfaces", interfaces_from_statistics(ifaces))
    |> put_section("uptime", uptime_from_activity(activity))
    |> put_section("system", system_from_information(info))
  end

  defp put_section(map, _key, nil), do: map
  defp put_section(map, _key, []), do: map
  defp put_section(map, key, value), do: Map.put(map, key, value)

  # -- direct-poll actions (xsense/client.py action half) -------------------

  @doc "Firmware status (agent-less path): current version, upgrade verdict."
  def firmware_status(%__MODULE__{} = c) do
    case get(c, "/api/core/firmware/status") do
      %{} = data ->
        %{
          "product_version" => data["product_version"] || data["product_version_running"] || "",
          "product_latest" => data["product_latest"] || "",
          "upgrade_available" => data["status"] == "update" or data["upgrade_available"] == true,
          "status_msg" => to_string(data["status_msg"] || data["status"] || "")
        }

      _ ->
        %{}
    end
  end

  @doc "Trigger a firmware update check (POST). {:ok, message} | {:error, msg}."
  def firmware_check(%__MODULE__{} = c) do
    case post(c, "/api/core/firmware/check") do
      %{} = data -> {:ok, to_string(data["status"] || "check triggered")}
      _ -> {:error, "firmware check failed"}
    end
  end

  @doc "Trigger a firmware update (POST)."
  def firmware_update(%__MODULE__{} = c) do
    case post(c, "/api/core/firmware/update") do
      %{} = data ->
        ok = String.contains?(String.downcase(inspect(data)), "ok") or data["status"] == "ok"
        {if(ok, do: :ok, else: :error), to_string(data["msg"] || data["status"] || "")}

      _ ->
        {:error, "firmware update failed"}
    end
  end

  @doc "Poll firmware upgrade progress: %{status, log}."
  def firmware_upgrade_status(%__MODULE__{} = c) do
    case get(c, "/api/core/firmware/upgradestatus") do
      %{} = data ->
        log = if is_binary(data["log"]), do: String.split(data["log"], "\n", trim: true), else: []
        %{status: to_string(data["status"] || "unknown"), log: log}

      _ ->
        %{status: "unknown", log: []}
    end
  end

  @doc "Restart the IPsec service (never per-tunnel — drops all; DR note)."
  def ipsec_restart(%__MODULE__{} = c) do
    action_result(post(c, "/api/ipsec/service/restart"), "ipsec restart")
  end

  @doc "Reboot the box (POST)."
  def reboot(%__MODULE__{} = c) do
    action_result(post(c, "/api/core/system/reboot"), "reboot")
  end

  # OPNsense action endpoints answer {"status":"ok"} / {"result":"ok"}.
  defp action_result(%{} = data, label) do
    body = String.downcase(inspect(data))
    ok = String.contains?(body, "\"ok\"") or data["status"] == "ok" or data["result"] == "ok"
    {if(ok, do: :ok, else: :error), to_string(data["status"] || data["result"] || label)}
  end

  defp action_result(_other, label), do: {:error, "#{label} failed"}

  @doc "Generic JSON GET/POST for the firewall-rules relay (direct path)."
  def api_json(%__MODULE__{} = c, "GET", path, _body) do
    case get(c, path) do
      nil -> {:error, :api_error}
      data -> {:ok, data}
    end
  end

  def api_json(%__MODULE__{} = c, "POST", path, body) do
    opts =
      [
        auth: {:basic, "#{c.api_key}:#{c.api_secret}"},
        json: body || %{},
        connect_options: [timeout: @connect_timeout, transport_opts: tls_opts(c.ssl_verify)],
        receive_timeout: @recv_timeout,
        retry: false
      ]
      |> maybe_test_plug()

    case Req.post(c.base_url <> path, opts) do
      {:ok, %{status: 200, body: b}} when is_map(b) or is_list(b) -> {:ok, b}
      _ -> {:error, :api_error}
    end
  rescue
    _ -> {:error, :api_error}
  end

  defp post(%__MODULE__{} = c, path) do
    opts =
      [
        auth: {:basic, "#{c.api_key}:#{c.api_secret}"},
        json: %{},
        connect_options: [timeout: @connect_timeout, transport_opts: tls_opts(c.ssl_verify)],
        receive_timeout: @recv_timeout,
        retry: false
      ]
      |> maybe_test_plug()

    case Req.post(c.base_url <> path, opts) do
      {:ok, %{status: 200, body: body}} when is_map(body) or is_list(body) -> body
      _ -> nil
    end
  rescue
    _ -> nil
  end

  @doc "Raw cpu section from systemResources (cpu.used → total_pct)."
  def cpu_from_resources(%{"cpu" => %{"used" => used}}) when not is_nil(used) do
    %{"total_pct" => to_float(used)}
  end

  def cpu_from_resources(_), do: nil

  @doc """
  Raw memory section from systemResources. total/used are bytes; *_frmt are
  MB — prefer the MB fields, else convert from bytes.
  """
  def memory_from_resources(%{"memory" => mem}) when is_map(mem) do
    total_mb = mb(mem["total_frmt"], mem["total"])
    used_mb = mb(mem["used_frmt"], mem["used"])
    used_pct = if total_mb > 0, do: Float.round(used_mb / total_mb * 100, 1), else: 0.0

    %{
      "total_mb" => Float.round(total_mb, 1),
      "used_mb" => Float.round(used_mb, 1),
      "used_pct" => used_pct,
      # No swap data from this endpoint — mark absent so swap_check returns nil.
      "swap_total_mb" => 0.0,
      "swap_used_pct" => 0.0
    }
  end

  def memory_from_resources(_), do: nil

  @doc "Raw disks section from systemDisk (devices[] → per-mount used_pct)."
  def disks_from_systemdisk(%{"devices" => devices}) when is_list(devices) do
    for d <- devices do
      %{
        "device" => d["device"] || "",
        "mountpoint" => d["mountpoint"] || d["type"] || "",
        "used_pct" => used_pct(d["used_pct"] || d["capacity"] || 0),
        "total_mb" => nil
      }
    end
  end

  def disks_from_systemdisk(devices) when is_list(devices),
    do: disks_from_systemdisk(%{"devices" => devices})

  def disks_from_systemdisk(_), do: []

  @doc """
  Raw interfaces section from getInterfaceStatistics (client.py
  interface_statistics port).

  OPNsense keys the map by a human label and repeats an interface once per
  address: `"[LAN] (vmx0) / 00:50:56:be:dd:5b" => %{"name" => "vmx0", …}`.
  Deduplicate on the short BSD name, keeping the first entry, and carry the
  zone prefix into the display name so the UI still shows "[LAN] vmx0".

  Byte counters land in `bytes_received`/`bytes_transmitted` — the same keys
  the agent push uses, so Metrics.rows_for_push writes one continuous
  iface.*.bytes_rx/tx series across transports.
  """
  def interfaces_from_statistics(%{"statistics" => stats}) when is_map(stats),
    do: interfaces_from_statistics(stats)

  def interfaces_from_statistics(stats) when is_map(stats) do
    stats
    |> Enum.reduce({[], MapSet.new()}, fn {label, info}, {acc, seen} ->
      short = iface_short_name(info, label)

      if is_map(info) and not MapSet.member?(seen, short) do
        {[iface_entry(short, label, info) | acc], MapSet.put(seen, short)}
      else
        {acc, seen}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  def interfaces_from_statistics(_), do: []

  defp iface_short_name(info, label) when is_map(info),
    do: to_string(info["name"] || String.slice(to_string(label), 0, 60))

  defp iface_short_name(_info, label), do: String.slice(to_string(label), 0, 60)

  defp iface_entry(short, label, info) do
    %{
      "name" => display_name(short, label),
      "status" => iface_status(info["flags"] || info["status"] || ""),
      "address" => info["address"],
      "bytes_received" => counter(info["received-bytes"] || info["bytes received"]),
      "bytes_transmitted" => counter(info["sent-bytes"] || info["bytes transmitted"])
    }
  end

  # "[LAN] (vmx0) / 00:…" → "[LAN] vmx0"; a label without a zone stays bare.
  defp display_name(short, label) do
    case String.split(to_string(label), "]", parts: 2) do
      ["[" <> _ = zone, _rest] -> String.trim("#{zone}] #{short}")
      _ -> short
    end
  end

  @doc "FreeBSD hex interface flags (0x8843) → up / up (not running) / down."
  def iface_status(""), do: "unknown"
  def iface_status(nil), do: "unknown"

  def iface_status("0x" <> _ = raw) do
    case Integer.parse(String.trim_leading(raw, "0x"), 16) do
      {flags, _} ->
        up = Bitwise.band(flags, 0x1) != 0
        running = Bitwise.band(flags, 0x40) != 0

        cond do
          up and running -> "up"
          up -> "up (not running)"
          true -> "down"
        end

      :error ->
        raw
    end
  end

  def iface_status(raw), do: to_string(raw)

  @doc """
  Uptime string from the activity endpoint header (client.py _parse_uptime).

  Header: `"last pid: 80943;  load averages: … up 1+18:18:17    10:16:21"`.
  Returns "1d 18h 18m" / "18h 18m" — a shape Metrics.uptime_to_seconds parses;
  nil when the header is missing, so no fake 0-uptime reboot enters the
  sawtooth series.
  """
  def uptime_from_activity(%{"headers" => headers}) when is_list(headers) do
    Enum.find_value(headers, fn line ->
      case Regex.run(~r/up\s+([\d+:]+)/, to_string(line)) do
        [_, raw] -> format_uptime(raw)
        nil -> nil
      end
    end)
  end

  def uptime_from_activity(_), do: nil

  defp format_uptime(raw) do
    case String.split(raw, "+", parts: 2) do
      [days, rest] ->
        case String.split(rest, ":") do
          [h, m | _] -> "#{days}d #{h}h #{m}m"
          _ -> raw
        end

      [clock] ->
        case String.split(clock, ":") do
          [h, m, _s] -> "#{h}h #{m}m"
          _ -> raw
        end
    end
  end

  @doc """
  Raw system section from system_information — hostname + running version, the
  two fields the detail page reads. Direct polls have no agent, so the
  agent-only keys of the push shape stay absent rather than being faked.
  """
  def system_from_information(%{} = data) do
    name = to_string(data["name"] || "")
    version = data |> Map.get("versions") |> first_version()

    case {name, version} do
      {"", nil} -> nil
      _ -> %{"hostname" => name, "os" => version || ""}
    end
  end

  def system_from_information(_), do: nil

  defp first_version([v | _]) when is_binary(v), do: v
  defp first_version(_), do: nil

  defp counter(n) when is_integer(n), do: n
  defp counter(n) when is_float(n), do: trunc(n)

  defp counter(s) when is_binary(s) do
    case Integer.parse(s) do
      {v, _} -> v
      :error -> 0
    end
  end

  defp counter(_), do: 0

  # -- HTTP -----------------------------------------------------------------

  defp get(%__MODULE__{} = c, path) do
    opts =
      [
        auth: {:basic, "#{c.api_key}:#{c.api_secret}"},
        connect_options: [timeout: @connect_timeout, transport_opts: tls_opts(c.ssl_verify)],
        receive_timeout: @recv_timeout,
        retry: false
      ]
      |> maybe_test_plug()

    case Req.get(c.base_url <> path, opts) do
      {:ok, %{status: 200, body: body}} when is_map(body) or is_list(body) -> body
      _ -> nil
    end
  rescue
    _ -> nil
  end

  # In :test a Req plug stub replaces the network (config :orbit,
  # :opnsense_req_plug). nil in dev/prod → real HTTP.
  defp maybe_test_plug(opts) do
    case Application.get_env(:orbit, :opnsense_req_plug) do
      nil -> opts
      plug -> Keyword.put(opts, :plug, plug)
    end
  end

  defp tls_opts(false), do: [verify: :verify_none]
  defp tls_opts(_), do: []

  defp mb(frmt, bytes) do
    from_frmt = num_or_zero(frmt)
    if from_frmt > 0, do: from_frmt, else: to_float(bytes) / 1024 / 1024
  end

  defp num_or_zero(n) when is_number(n) and n > 0, do: n / 1
  defp num_or_zero(s) when is_binary(s), do: parse_num(s)
  defp num_or_zero(_), do: 0.0

  defp used_pct(raw) when is_number(raw), do: raw / 1
  defp used_pct(raw) when is_binary(raw), do: raw |> String.trim_trailing("%") |> parse_num()
  defp used_pct(_), do: 0.0

  defp to_float(n) when is_number(n), do: n / 1
  defp to_float(n) when is_binary(n), do: parse_num(n)
  defp to_float(_), do: 0.0

  defp parse_num(s) do
    case Float.parse(to_string(s)) do
      {v, _} -> v
      :error -> 0.0
    end
  end
end
