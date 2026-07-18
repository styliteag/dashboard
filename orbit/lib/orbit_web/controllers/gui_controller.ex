defmodule OrbitWeb.GuiController do
  @moduledoc """
  GUI-proxy HTTP surface (routes/gui.py port).

  - `open` (POST, write-gated): scope the instance, refuse device types
    without a web UI, require a connected agent, ensure the forwarder +
    Caddy vhost, mint a 60s handoff token; when gui_login_enabled, replay
    the firewall login via the agent and stash its cookies for handoff.
    Audits agent.gui_open. Returns the handoff URL.
  - `handoff` (GET): exchange a valid token for an 8h orbit_gui cookie
    (+ any stashed firewall cookies), redirect to the safe next path.
    EXEMPT from the geo gate (container-to-container subrequest).
  - `authcheck` (GET): forward_auth target — 200 only when the orbit_gui
    cookie is valid for THIS instance (zero-I/O HMAC verify, cross-tenant
    defense). EXEMPT from the geo gate.
  """

  use OrbitWeb, :controller

  require Logger

  alias Orbit.Auth.Scope
  alias Orbit.GUI
  alias Orbit.GUI.Auth
  alias Orbit.Hub
  alias Orbit.Instances.Instance

  @cookie_name Auth.cookie_name()

  def open(conn, %{"instance_id" => raw_id} = params) do
    user = conn.assigns.current_user

    with true <- Application.get_env(:orbit, :gui_proxy_enabled, false) or :disabled,
         {id, ""} <- Integer.parse(raw_id),
         %Instance{} = inst <- Scope.get_instance(id, user),
         true <- webif?(inst) or :no_webif,
         %Orbit.Hub.Agent{} <- Hub.get(id) do
      Orbit.GUI.TunnelManager.ensure(id)
      Orbit.GUI.Caddy.reconcile()
      token = Auth.sign(id, 60)
      maybe_stash_login(inst, token)

      Orbit.Audit.write(
        action: "agent.gui_open",
        result: "ok",
        user_id: user.id,
        target_type: "instance",
        target_id: id,
        source_ip: client_ip(conn)
      )

      json(conn, %{url: GUI.handoff_url(inst, token, params["path"])})
    else
      :disabled -> conn |> put_status(404) |> json(%{detail: "gui proxy disabled"})
      :no_webif -> conn |> put_status(400) |> json(%{detail: "this device type has no web ui"})
      nil -> conn |> put_status(503) |> json(%{detail: "agent not connected"})
      # missing / out-of-scope → 404 (no oracle).
      _ -> conn |> put_status(404) |> json(%{detail: "not found"})
    end
  end

  def handoff(conn, params) do
    case Auth.verify(params["t"] || "") do
      nil ->
        conn |> put_status(403) |> text("invalid handoff token")

      instance_id ->
        conn
        |> put_gui_cookie(instance_id)
        |> put_stashed_cookies(params["t"])
        |> redirect(to: GUI.safe_next(params["next"]))
    end
  end

  def authcheck(conn, params) do
    instance = instance_from_request(conn, params)
    token = conn.cookies[@cookie_name] || ""
    cookie_instance = if token != "", do: Auth.verify(token)

    if instance != nil and cookie_instance == instance do
      json(conn, %{ok: true})
    else
      conn |> put_status(401) |> json(%{detail: "gui auth required"})
    end
  end

  # -- helpers ---------------------------------------------------------------

  defp webif?(%Instance{device_type: dt}), do: dt not in ["linux"]

  defp maybe_stash_login(%Instance{gui_login_enabled: true, id: id}, token) do
    case Hub.send_command(id, "gui.login", %{}, 20_000) do
      %{"success" => true, "cookies" => cookies} when is_list(cookies) ->
        pairs = for c <- cookies, is_map(c), do: {c["name"], c["value"]}
        Orbit.GUI.SessionStash.put(token, pairs, 60)

      other ->
        Logger.warning("agent.gui_login_failed instance=#{id} output=#{inspect(other["output"])}")
    end
  end

  defp maybe_stash_login(_inst, _token), do: :ok

  defp put_gui_cookie(conn, instance_id) do
    # 8h browsing-session cookie (parity with the python set_cookie).
    put_resp_cookie(conn, @cookie_name, Auth.sign(instance_id, 8 * 3600),
      http_only: true,
      secure: true,
      same_site: "Lax",
      path: "/"
    )
  end

  defp put_stashed_cookies(conn, token) do
    Enum.reduce(Orbit.GUI.SessionStash.pop(token), conn, fn {name, value}, acc ->
      put_resp_cookie(acc, name, value,
        http_only: true,
        secure: true,
        same_site: "Lax",
        path: "/"
      )
    end)
  end

  # instance from the ?instance= query (dev per-port) or the gui-<id> host
  # (prod wildcard, via X-Forwarded-Host) — server-side, not spoofable.
  defp instance_from_request(conn, params) do
    case Integer.parse(to_string(params["instance"] || "")) do
      {n, ""} ->
        n

      _ ->
        host =
          get_req_header(conn, "x-forwarded-host") |> List.first() ||
            get_req_header(conn, "host") |> List.first() || ""

        case Regex.run(~r/^gui-(\d+)\./, host) do
          [_, id] -> String.to_integer(id)
          _ -> nil
        end
    end
  end

  defp client_ip(conn), do: Orbit.Net.client_ip(conn)
end
