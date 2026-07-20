defmodule Orbit.Securepoint.Client do
  @moduledoc """
  Securepoint UTM spcgi client — port of securepoint/client.py's core.
  Pull model (no on-box agent): the appliance exposes a JSON `/spcgi.cgi`
  endpoint.

  - Session auth: `auth login` returns a top-level `sessionid` echoed in
    every later request.
  - Request envelope: `{module, command: [...], arguments: {...}, sessionid}`.
  - Response envelope: `{sessionid, result: {code, status, content}}` — the
    payload is `result.content`; `code >= 400` is an error.

  Security invariant (carried from python): NEVER call `ipsec get` — that
  command returns the IPsec pre-shared key in plaintext. Only `ipsec
  status` (no secrets) is allowed; the forbidden pair is refused before any
  request. Test seam: `opts[:req_plug]`.
  """

  @spcgi_path "/spcgi.cgi"
  @forbidden [{"ipsec", "get"}]

  defstruct [:base_url, :user, :password, :ssl_verify, :ca_bundle, :sessionid, :req_plug]

  @type t :: %__MODULE__{}

  @doc "Build an unauthenticated client from an instance (decrypts creds)."
  def new(inst, opts \\ []) do
    with {:ok, user} <- Orbit.Crypto.decrypt(inst.api_key_enc),
         {:ok, password} <- Orbit.Crypto.decrypt(inst.api_secret_enc) do
      {:ok,
       %__MODULE__{
         base_url: Orbit.Instances.Instance.primary_base_url(inst) |> String.trim_trailing("/"),
         user: user,
         password: password,
         ssl_verify: inst.ssl_verify,
         ca_bundle: inst.ca_bundle,
         req_plug:
           Keyword.get(opts, :req_plug, Application.get_env(:orbit, :securepoint_req_plug))
       }}
    end
  end

  @doc "Open a session; returns {:ok, client_with_sessionid} | {:error, msg}."
  def login(%__MODULE__{} = c) do
    payload = %{
      "module" => "auth",
      "command" => ["login"],
      "arguments" => %{"user" => c.user, "pass" => c.password}
    }

    with {:ok, data} <- post(c, payload),
         result = data["result"] || %{},
         true <-
           code(result) < 400 or {:error, "login failed: #{result["message"] || "unauthorized"}"},
         sid when is_binary(sid) or is_integer(sid) <-
           data["sessionid"] || {:error, "no sessionid"} do
      {:ok, %{c | sessionid: to_string(sid)}}
    else
      {:error, _} = err -> err
      _ -> {:error, "login failed"}
    end
  end

  @doc """
  Run a spcgi command → {:ok, content} | {:error, msg}. Ensures a session
  (lazy login), refuses the secret-leaking forbidden commands.
  """
  def command(%__MODULE__{} = c, module, cmd, args \\ %{}) do
    cond do
      {module, hd(cmd)} in @forbidden ->
        {:error, "refusing '#{module} #{Enum.join(cmd, " ")}': leaks secrets"}

      c.sessionid == nil ->
        with {:ok, c} <- login(c), do: run(c, module, cmd, args)

      true ->
        run(c, module, cmd, args)
    end
  end

  @doc """
  Live status of a Securepoint box as raw sections for the checks engine.

  Emits the SAME section shapes the OPNsense client does (cpu/memory/disks/
  interfaces/uptime/system), so one evaluation path serves both vendors and the
  detail page needs no per-vendor branch.

  The numbers come from `system info`, which returns live stats as
  `{attribute, value}` rows — User/System/Idle %, Mem Total/Avail (KiB),
  storage/storage free (bytes), Uptime. Interface byte counters are NOT exposed
  by this JSON API (RRD only), so the counters stay 0 and only addresses and
  up/down are filled.

  Regression: this used to fetch `appmgmt get_information` and hand the raw
  payload through as the "system" section. That endpoint carries none of the
  live stats, so every Securepoint box rendered without CPU, memory, disk,
  uptime or interface data — the metrics surface the python client had filled
  since day one (`poll_status`, "fills the same metrics surface as OPNsense").

  Best-effort per section: a failing command yields no section, never a crash.
  """
  def fetch_status(%__MODULE__{} = c) do
    with {:ok, c} <- login(c) do
      info = system_info(c)

      %{}
      |> maybe_put("cpu", cpu_from_info(info))
      |> maybe_put("memory", memory_from_info(info))
      |> maybe_put("loadavg", loadavg_from_info(info))
      |> maybe_put("disks", disks_from_info(info))
      |> maybe_put("uptime", info["Uptime"])
      |> maybe_put("system", system_from_info(info))
      |> maybe_put("interfaces", interfaces(c))
      |> maybe_put("firmware", firmware_from_info(info))
      |> maybe_put("openvpn", section(c, "openvpn", ["status"]))
      |> maybe_put("ipsec", section(c, "ipsec", ["status"]))
    else
      _ -> %{}
    end
  end

  @doc """
  `system info` flattened to an attribute map.

  The endpoint returns `[%{"attribute" => k, "value" => v}, ...]` (hostname,
  version, productname, Idle, Mem Total, …) — collapsed to `%{k => v}`.
  """
  def system_info(%__MODULE__{} = c) do
    case section(c, "system", ["info"]) do
      rows when is_list(rows) -> flatten_info(rows)
      _ -> %{}
    end
  end

  @doc false
  def flatten_info(rows) when is_list(rows) do
    for %{"attribute" => k} = row <- rows, into: %{} do
      {to_string(k), to_string(Map.get(row, "value", ""))}
    end
  end

  def flatten_info(_), do: %{}

  @doc """
  Parse a Securepoint number that may carry a percent sign and padding:
  `"  98%"` → `98.0`. Unparseable input is 0.0, never an error — a single odd
  attribute must not blank the whole section.
  """
  def num(raw) do
    case raw
         |> to_string()
         |> String.trim()
         |> String.trim_trailing("%")
         |> String.trim()
         |> Float.parse() do
      {v, _} -> v
      :error -> 0.0
    end
  end

  @doc "CPU busy % — `system info` reports per-state %, busy = 100 - Idle."
  def cpu_from_info(%{"Idle" => idle}), do: %{"total_pct" => Float.round(100.0 - num(idle), 1)}
  def cpu_from_info(_), do: nil

  @doc "Memory section from Mem Total / Mem Avail (KiB)."
  def memory_from_info(info) when is_map(info) do
    total_kb = num(Map.get(info, "Mem Total", "0"))
    avail_kb = num(Map.get(info, "Mem Avail", "0"))

    if total_kb <= 0 do
      nil
    else
      used_kb = max(total_kb - avail_kb, 0.0)

      %{
        "total_mb" => Float.round(total_kb / 1024, 1),
        "used_mb" => Float.round(used_kb / 1024, 1),
        "used_pct" => Float.round(used_kb / total_kb * 100, 1)
      }
      |> Map.merge(swap_from_info(info))
    end
  end

  def memory_from_info(_), do: nil

  @doc """
  Swap from `Swap Total` / `Swap Free` (KiB, same unit as the Mem fields).

  A box without a swap device reports 0, and 0 is the documented no-data
  sentinel — `swap_check/1` returns nil on `swap_total_mb <= 0` rather than
  alarming on an absent feature (incident c37de13). So the sentinel is DERIVED
  here, not assumed: a box that does have swap gets monitored.
  """
  def swap_from_info(info) when is_map(info) do
    total_kb = num(Map.get(info, "Swap Total", "0"))
    free_kb = num(Map.get(info, "Swap Free", "0"))

    if total_kb <= 0 do
      %{"swap_total_mb" => 0.0, "swap_used_pct" => 0.0}
    else
      used_kb = max(total_kb - free_kb, 0.0)

      %{
        "swap_total_mb" => Float.round(total_kb / 1024, 1),
        "swap_used_pct" => Float.round(used_kb / total_kb * 100, 1)
      }
    end
  end

  def swap_from_info(_), do: %{"swap_total_mb" => 0.0, "swap_used_pct" => 0.0}

  @doc """
  Load averages from the `loadavg` attribute (`"0.42, 0.31, 0.28"`), with the
  core count so the UI can show "load (N cores)".

  Without this the metric writer stored load.1m/5m/15m as a flat 0 for every
  Securepoint box — fabricated data, which reads as a healthy idle box rather
  than as "not measured".
  """
  def loadavg_from_info(info) when is_map(info) do
    case Map.get(info, "loadavg") do
      raw when is_binary(raw) ->
        case raw |> String.split(~r/[,\s]+/, trim: true) |> Enum.map(&num/1) do
          [one, five, fifteen | _] ->
            %{"one" => one, "five" => five, "fifteen" => fifteen}
            |> maybe_cores(Map.get(info, "CPU Cores"))

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  def loadavg_from_info(_), do: nil

  defp maybe_cores(load, nil), do: load

  defp maybe_cores(load, raw) do
    case trunc(num(raw)) do
      n when n > 0 -> Map.put(load, "cores", n)
      _ -> load
    end
  end

  @doc "The persistent /data volume from `storage` / `storage free` (bytes)."
  def disks_from_info(info) when is_map(info) do
    total = num(Map.get(info, "storage", "0"))
    free = num(Map.get(info, "storage free", "0"))

    if total <= 0 do
      []
    else
      [
        %{
          "device" => "/data",
          "mountpoint" => "/data",
          "used_pct" => Float.round((total - free) / total * 100, 1),
          "total_mb" => Float.round(total / 1_048_576, 1)
        }
      ]
    end
  end

  def disks_from_info(_), do: []

  @doc "Hostname + version, falling back to the product fields."
  def system_from_info(info) when is_map(info) do
    name = Map.get(info, "hostname") || Map.get(info, "productname") || ""
    version = Map.get(info, "version") || Map.get(info, "productversion") || ""

    case {name, version} do
      {"", ""} -> nil
      _ -> %{"hostname" => name, "os" => version}
    end
  end

  def system_from_info(_), do: nil

  @doc """
  Firmware state from `system info`: `version`/`cur` is installed, `new` is the
  available upgrade ("none" or "-" when up to date).

  Same section shape the OPNsense client emits, so the Firmware tab and
  `Evaluate.firmware_check/1` (the "Update available: X → Y" WARN) work for a
  Securepoint box without a per-vendor branch.

  Securepoint firmware is READ-ONLY from here: the python client answered its
  check/update/reboot actions with a not-supported result and this port keeps
  that — only the status is real. `security_updates` stays 0 because the API
  does not classify updates; a plain `upgrade_available` yields the plain WARN.
  """
  def firmware_from_info(info) when is_map(info) do
    installed = Map.get(info, "version") || Map.get(info, "cur") || ""
    available = Map.get(info, "new", "")

    upgrade? =
      available != "" and String.downcase(available) not in ["none", "-"] and
        available != installed

    case installed do
      "" ->
        nil

      _ ->
        %{
          "product_version" => installed,
          "product_latest" => if(upgrade?, do: available, else: installed),
          "upgrade_available" => upgrade?,
          "updates_available" => if(upgrade?, do: 1, else: 0),
          "security_updates" => 0,
          "needs_reboot" => false,
          "check_failed" => false
        }
    end
  end

  def firmware_from_info(_), do: nil

  @doc """
  Interfaces with their addresses. `ONLINE`/`DYNAMIC` in flags means up.

  Byte counters are not in this API (RRD only) — emitted as 0 so
  Metrics.rows_for_push keeps one continuous series shape across vendors
  without inventing traffic.
  """
  def interfaces(%__MODULE__{} = c) do
    case section(c, "interface", ["address", "get"]) do
      rows when is_list(rows) -> Enum.map(rows, &interface_row/1)
      _ -> []
    end
  end

  @doc false
  def interface_row(row) when is_map(row) do
    flags = if is_list(row["flags"]), do: row["flags"], else: []
    up? = "ONLINE" in flags or "DYNAMIC" in flags

    %{
      "name" => to_string(row["device"] || ""),
      "status" => if(up?, do: "up", else: "down"),
      "address" => row["address"],
      "bytes_received" => 0,
      "bytes_transmitted" => 0
    }
  end

  def interface_row(_), do: %{}

  # -- internals ------------------------------------------------------------

  defp section(c, module, cmd) do
    case command(c, module, cmd) do
      {:ok, content} -> content
      _ -> nil
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, []), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp run(%__MODULE__{} = c, module, cmd, args) do
    payload = %{
      "module" => module,
      "command" => cmd,
      "arguments" => args,
      "sessionid" => c.sessionid
    }

    with {:ok, data} <- post(c, payload) do
      unwrap(data, "#{module} #{Enum.join(cmd, " ")}")
    end
  end

  defp unwrap(data, what) do
    result = data["result"] || %{}

    if code(result) >= 400 do
      {:error, "#{what}: #{code(result)} #{result["message"] || result["status"] || "error"}"}
    else
      {:ok, result["content"] || []}
    end
  end

  defp code(result) do
    case result["code"] do
      n when is_integer(n) -> n
      s when is_binary(s) -> String.to_integer(s)
      _ -> 0
    end
  rescue
    _ -> 0
  end

  defp post(%__MODULE__{} = c, payload) do
    base = [
      url: c.base_url <> @spcgi_path,
      json: payload,
      headers: [{"accept", "application/json"}],
      connect_options: [transport_opts: tls_opts(c)],
      receive_timeout: 10_000,
      retry: false
    ]

    req_opts = if c.req_plug, do: Keyword.put(base, :plug, c.req_plug), else: base

    case Req.post(req_opts) do
      {:ok, %{status: status, body: body}} when status < 400 and is_map(body) ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, "POST #{@spcgi_path}: HTTP #{status}"}

      {:error, error} ->
        {:error, "POST #{@spcgi_path}: #{Exception.message(error)}"}
    end
  end

  # No bundle keeps the previous behaviour exactly (explicit verify_peer);
  # a stored CA bundle pins verification to it instead.
  defp tls_opts(%__MODULE__{ssl_verify: false}), do: [verify: :verify_none]

  defp tls_opts(%__MODULE__{ca_bundle: bundle}),
    do: Orbit.Net.TLS.bundle_opts(bundle) || [verify: :verify_peer]
end
