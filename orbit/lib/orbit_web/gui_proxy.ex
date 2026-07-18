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

  alias Orbit.GUI.Auth
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
    if Auth.verify(conn.query_params["t"] || "") == id do
      conn
      |> put_resp_cookie(@cookie, Auth.sign(id, 8 * 3600),
        http_only: true,
        same_site: "Lax",
        path: "/"
      )
      |> put_resp_header("location", Orbit.GUI.safe_next(conn.query_params["next"]))
      |> send_resp(302, "")
      |> halt()
    else
      conn |> send_resp(403, "invalid handoff token") |> halt()
    end
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
      _ ->
        conn |> send_resp(502, "firewall gui unavailable") |> halt()
    end
  end

  defp forward(conn, port, body) do
    url = "https://127.0.0.1:#{port}#{conn.request_path}"
    url = if conn.query_string == "", do: url, else: url <> "?" <> conn.query_string

    headers =
      conn.req_headers
      |> Enum.reject(fn {k, _} -> k in ["host", "connection", "content-length"] end)

    Req.request(
      method: conn.method |> String.downcase() |> String.to_atom(),
      url: url,
      headers: headers,
      body: body,
      redirect: false,
      retry: false,
      receive_timeout: 30_000,
      connect_options: [transport_opts: [verify: :verify_none]],
      decode_body: false
    )
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
