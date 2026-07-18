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

    %{}
    |> put_section("cpu", cpu_from_resources(resources))
    |> put_section("memory", memory_from_resources(resources))
    |> put_section("disks", disks_from_systemdisk(disk))
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
