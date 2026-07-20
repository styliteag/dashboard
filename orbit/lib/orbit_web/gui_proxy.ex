defmodule OrbitWeb.GuiProxy do
  @moduledoc """
  Host-matched GUI reverse proxy on the SAME port as the app (§18) — the
  whole GUI proxy, in dev and in prod. A request whose Host is a GUI origin
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
        secure: https?(conn),
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
        secure: https?(conn),
        same_site: "Lax",
        path: "/"
      )
    end)
  end

  # Read the forwarded scheme directly instead of trusting conn.scheme. In
  # prod conn.scheme is ALREADY :https here — prod.exs sets force_ssl with
  # rewrite_on: [:x_forwarded_proto], and Plug.SSL is the endpoint's first
  # plug, ahead of this one — so this is belt-and-braces, not a live fix.
  # It exists because a cookie's Secure flag should not silently depend on
  # an endpoint setting three layers away: drop force_ssl (or run this plug
  # in a config without it) and an https GUI origin would otherwise get a
  # cookie without Secure, which the browser then also sends over http.
  # Spoofing the header cannot weaken anything (a forged "https" only adds
  # Secure, which a plain-http origin then refuses to store).
  defp https?(conn) do
    conn.scheme == :https or
      List.first(get_req_header(conn, "x-forwarded-proto")) == "https"
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
         {:ok, body, conn} <- read_body(conn, length: 25_000_000) do
      case forward_with_retry(conn, port, body, 4) do
        # SSE / chunked response: already streamed to the browser (send_chunked
        # + chunk in the callback), the conn is sent — just hand it back.
        {:streamed, conn} ->
          conn

        {:buffered, resp} ->
          send_upstream(conn, resp)

        other ->
          Logger.warning(
            "gui_proxy.forward_failed path=#{conn.request_path} err=#{inspect(other)}"
          )

          conn |> send_resp(502, "firewall gui unavailable") |> halt()
      end
    else
      other ->
        Logger.warning("gui_proxy.forward_failed path=#{conn.request_path} err=#{inspect(other)}")
        conn |> send_resp(502, "firewall gui unavailable") |> halt()
    end
  end

  # The FIRST request after a fresh forwarder races the tunnel bring-up:
  # tcp accept → agent open_tunnel → on-box connect → TLS/h2 handshake all
  # happen on demand, and the h2 pool answers :pool_not_available until the
  # connection stands (user report: first tab load 502s, reload works). These
  # connection-establishment failures never reached the firewall (nothing was
  # streamed yet), so the retry is safe for any method.
  @retryable_reasons [:pool_not_available, :closed, :econnrefused, :connect_timeout]

  defp forward_with_retry(conn, port, body, attempts_left) do
    case forward(conn, port, body) do
      {:error, %{reason: reason}} = err when reason in @retryable_reasons ->
        if attempts_left > 1 do
          Process.sleep(250)
          forward_with_retry(conn, port, body, attempts_left - 1)
        else
          err
        end

      other ->
        other
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

    do_forward(conn, method, url, headers, body, retries_left(method))
  end

  # GET/HEAD are safe to replay; a mutating method must never be retried.
  defp retries_left(m) when m in [:get, :head], do: 3
  defp retries_left(_), do: 0

  # Stream the response off the firewall. A text/event-stream (OPNsense's
  # live traffic/log/CPU widgets) is passed through with send_chunked/chunk
  # so it never buffers to completion (that timed out — user report); every
  # other response accumulates and returns {:buffered, resp} for the
  # existing send path. The h2 corruption + concurrency notes above still
  # hold — this is the same Finch h2 pool, just streamed.
  defp do_forward(conn, method, url, headers, body, retries) do
    req =
      Finch.build(method, url, headers, if(body == "", do: nil, else: body))

    acc = %{status: nil, resp_headers: [], body: [], mode: :buffer, conn: conn}

    try do
      # receive_timeout is BETWEEN chunks — an idle SSE stream past this errors
      # and closes; the browser's EventSource just reconnects. request_timeout
      # off so a long-lived stream isn't capped as a whole.
      case Finch.stream(req, Orbit.GUI.Finch, acc, &stream_step/2,
             receive_timeout: 65_000,
             request_timeout: :infinity
           ) do
        {:ok, %{mode: :stream, conn: conn}} ->
          {:streamed, conn}

        {:ok, %{status: status, resp_headers: hs, body: iodata}} ->
          {:buffered, %{status: status, headers: hs, body: IO.iodata_to_binary(iodata)}}

        # Finch.stream error tuple carries the accumulator as a third element.
        {:error, %{reason: :too_many_concurrent_requests}, _acc} when retries > 0 ->
          # All h2 streams on a connection are busy — transient (~ms); retry
          # idempotent methods rather than 502 mid-page.
          Process.sleep(15)
          do_forward(conn, method, url, headers, body, retries - 1)

        {:error, reason, _acc} ->
          {:error, reason}
      end
    catch
      # The browser hung up mid-stream — normal for SSE (tab closed, nav away).
      {:client_gone, streamed_conn} -> {:streamed, streamed_conn}
    end
  end

  # Finch.stream callback (threads the acc map).
  defp stream_step({:status, status}, acc), do: %{acc | status: status}

  defp stream_step({:headers, headers}, acc) do
    if sse?(headers) do
      conn = acc.conn |> copy_headers(headers) |> Plug.Conn.send_chunked(acc.status)
      %{acc | resp_headers: headers, mode: :stream, conn: conn}
    else
      %{acc | resp_headers: headers}
    end
  end

  defp stream_step({:data, data}, %{mode: :stream, conn: conn} = acc) do
    case Plug.Conn.chunk(conn, data) do
      {:ok, conn} -> %{acc | conn: conn}
      {:error, _closed} -> throw({:client_gone, conn})
    end
  end

  defp stream_step({:data, data}, acc), do: %{acc | body: [acc.body | [data]]}
  defp stream_step(_other, acc), do: acc

  defp sse?(headers) do
    Enum.any?(headers, fn {k, v} ->
      String.downcase(to_string(k)) == "content-type" and
        v |> to_string() |> String.downcase() |> String.contains?("text/event-stream")
    end)
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
