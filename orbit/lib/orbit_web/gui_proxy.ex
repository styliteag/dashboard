defmodule OrbitWeb.GuiProxy do
  @moduledoc """
  Host-matched GUI reverse proxy on the SAME port as the app (§18, orbit-
  native — no Caddy). A request whose Host is a GUI origin
  (`<slug>.localhost` in dev, `gui-<slug>.<domain>` in prod) is handled
  here, before the router:

  - `/__orbit/auth?t=<token>` — the handoff: verify the HMAC token, set the
    origin-scoped `orbit_gui` cookie, redirect to the next path. Runs ON the
    GUI host so the cookie is scoped to it.
  - anything else — gate on the `orbit_gui` cookie (must be valid for THIS
    instance, cross-tenant defense), then reverse-proxy to the firewall GUI
    through this instance's internal TCP forwarder (127.0.0.1:14400+id → the
    agent tunnel). The browser speaks plain HTTP to orbit; orbit speaks the
    firewall's own HTTPS over the transparent forwarder.

  A non-GUI host (the app's own origin) passes straight through untouched.
  """

  @behaviour Plug

  import Plug.Conn
  require Logger

  alias Orbit.GUI.Auth
  alias Orbit.GUI.SessionStash
  alias Orbit.GUI.TunnelManager

  @cookie Auth.cookie_name()

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case slug_from_host(conn.host) do
      nil -> conn
      slug -> handle(conn, slug)
    end
  end

  defp handle(conn, slug) do
    case instance_for(slug) do
      nil ->
        conn |> send_resp(404, "unknown gui host") |> halt()

      %{id: id} ->
        conn = fetch_query_params(conn)

        if conn.request_path == "/__orbit/auth" do
          handoff(conn, id)
        else
          gated_proxy(conn, id)
        end
    end
  end

  defp handoff(conn, id) do
    token = conn.query_params["t"] || ""

    if Auth.verify(token) == id do
      conn
      |> put_resp_cookie(@cookie, Auth.sign(id, 8 * 3600),
        http_only: true,
        secure: conn.scheme == :https,
        same_site: "Lax",
        path: "/"
      )
      |> put_stashed_cookies(token)
      |> put_resp_header("location", Orbit.GUI.safe_next(conn.query_params["next"]))
      |> send_resp(302, "")
      |> halt()
    else
      conn |> send_resp(403, "invalid handoff token") |> halt()
    end
  end

  # Replay the firewall's own session cookies (stashed at gui/open by the
  # agent's gui.login) onto THIS proxy origin, so the very first proxied
  # request already carries a logged-in session — the pre-authentication.
  # Origin-scoped (path "/", same_site Lax); secure only when the proxy
  # origin is https (dev is plain http on <slug>.localhost, so no secure).
  defp put_stashed_cookies(conn, token) do
    Enum.reduce(SessionStash.pop(token), conn, fn {name, value}, acc ->
      put_resp_cookie(acc, name, value,
        http_only: true,
        secure: conn.scheme == :https,
        same_site: "Lax",
        path: "/"
      )
    end)
  end

  defp gated_proxy(conn, id) do
    conn = fetch_cookies(conn)
    token = conn.req_cookies[@cookie] || ""

    if Auth.verify(token) == id do
      proxy(conn, id)
    else
      conn
      |> send_resp(401, "GUI session expired — reopen from the dashboard.")
      |> halt()
    end
  end

  defp proxy(conn, id) do
    with {:ok, port} <- TunnelManager.ensure(id),
         {:ok, body, conn} <- read_body(conn, length: 25_000_000),
         {:ok, resp} <- forward(conn, port, body) do
      send_upstream(conn, resp)
    else
      other ->
        Logger.warning("gui_proxy.forward_failed path=#{conn.request_path} err=#{inspect(other)}")
        conn |> send_resp(502, "firewall gui unavailable") |> halt()
    end
  end

  # Speak HTTP/2 to the firewall — the same protocol the browser and every other
  # client negotiate with OPNsense/pfSense. This is NOT cosmetic: OPNsense's
  # lighttpd serves large *uncompressed* static files (e.g. tabulator.min.js,
  # main.css) with a deterministic body-corruption bug over HTTP/1.1 — clean over
  # HTTP/2. Proven live: h1.1+identity corrupts every time, h2 is byte-perfect
  # (the transparent TLS tunnel is provably intact — TLS integrity would break
  # otherwise). HTTP/2 also multiplexes the whole page load onto one connection,
  # sidestepping the HTTP/1 keep-alive pool reuse that produced :invalid_status_
  # line 502s under concurrent asset fetches. No Connection header (forbidden in
  # h2); Req passes the body through raw (decode_body: false) so content-encoding
  # from the firewall reaches the browser untouched.
  defp forward(conn, port, body) do
    url = "https://127.0.0.1:#{port}#{conn.request_path}"
    url = if conn.query_string == "", do: url, else: url <> "?" <> conn.query_string
    method = conn.method |> String.downcase() |> String.to_atom()

    headers =
      conn.req_headers
      |> Enum.reject(fn {k, _} -> k in ["host", "connection", "content-length"] end)

    do_forward(method, url, headers, body, retries_left(method))
  end

  # GET/HEAD are safe to replay; a mutating method must never be retried.
  defp retries_left(m) when m in [:get, :head], do: 3
  defp retries_left(_), do: 0

  defp do_forward(method, url, headers, body, retries) do
    result =
      Req.request(
        finch: Orbit.GUI.Finch,
        method: method,
        url: url,
        headers: headers,
        # nil (not "") for bodyless methods: an empty DATA frame makes lighttpd's
        # h2 parser 400 a GET.
        body: if(body == "", do: nil, else: body),
        redirect: false,
        retry: false,
        receive_timeout: 30_000,
        decode_body: false
      )

    # All h2 streams on a connection are busy — transient, a stream frees within
    # a few ms; retry idempotent methods instead of surfacing a 502 mid-page.
    case result do
      {:error, %Req.HTTPError{reason: :too_many_concurrent_requests}} when retries > 0 ->
        Process.sleep(15)
        do_forward(method, url, headers, body, retries - 1)

      other ->
        other
    end
  end

  defp send_upstream(conn, resp) do
    conn
    |> copy_headers(resp.headers)
    |> send_resp(resp.status, resp.body)
    |> halt()
  end

  # Copy the firewall's response headers, dropping hop-by-hop ones and
  # rewriting an absolute Location back onto this origin.
  defp copy_headers(conn, headers) do
    drop = ~w(connection transfer-encoding content-length keep-alive)

    Enum.reduce(headers, conn, fn {k, v}, acc ->
      k = String.downcase(to_string(k))
      value = v |> List.wrap() |> List.first() |> to_string()

      cond do
        k in drop -> acc
        k == "location" -> put_resp_header(acc, "location", rewrite_location(value, conn))
        true -> put_resp_header(acc, k, value)
      end
    end)
  end

  # https://127.0.0.1:<port>/x → keep just the path on this origin.
  defp rewrite_location(loc, _conn) do
    case URI.parse(loc) do
      %URI{host: "127.0.0.1"} = u -> u.path <> if(u.query, do: "?" <> u.query, else: "")
      _ -> loc
    end
  end

  # -- host / instance resolution -------------------------------------------

  # dev: "<slug>.localhost" (but not bare "localhost"); prod: "gui-<slug>.<domain>".
  defp slug_from_host(host) when is_binary(host) do
    cond do
      match = Regex.run(~r/^gui-([a-z0-9-]+)\./, host) -> Enum.at(match, 1)
      host == "localhost" -> nil
      match = Regex.run(~r/^([a-z0-9-]+)\.localhost$/, host) -> Enum.at(match, 1)
      true -> nil
    end
  end

  defp slug_from_host(_), do: nil

  defp instance_for(slug) do
    import Ecto.Query

    Orbit.Repo.one(
      from(i in Orbit.Instances.Instance,
        where: i.slug == ^slug and is_nil(i.deleted_at),
        select: %{id: i.id}
      )
    )
  rescue
    _ -> nil
  end
end
