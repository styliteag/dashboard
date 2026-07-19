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

  defstruct [:base_url, :user, :password, :ssl_verify, :sessionid, :req_plug]

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
  Live status of a Securepoint box as raw sections for the checks engine:
  system info + openvpn + ipsec status. Best-effort per section (a failing
  command yields no section, never a crash — mirrors the python gather).
  """
  def fetch_status(%__MODULE__{} = c) do
    with {:ok, c} <- login(c) do
      %{}
      |> maybe_put("system", section(c, "appmgmt", ["get_information"]))
      |> maybe_put("openvpn", section(c, "openvpn", ["status"]))
      |> maybe_put("ipsec", section(c, "ipsec", ["status"]))
    else
      _ -> %{}
    end
  end

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
      connect_options: [transport_opts: tls_opts(c.ssl_verify)],
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

  defp tls_opts(false), do: [verify: :verify_none]
  defp tls_opts(_), do: [verify: :verify_peer]
end
