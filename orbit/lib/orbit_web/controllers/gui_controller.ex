defmodule OrbitWeb.GuiController do
  @moduledoc """
  GUI-proxy HTTP surface (routes/gui.py port).

  One route: `open` (POST, write-gated) — scope the instance, refuse device
  types without a web UI, require a connected agent, ensure the forwarder,
  mint a 60s handoff token; when gui_login_enabled, replay the firewall
  login via the agent and stash its cookies for handoff. Audits
  agent.gui_open. Returns the handoff URL.

  The handoff exchange and the per-asset gate are NOT here: they live in
  `OrbitWeb.GuiProxy`, which runs on the GUI origin itself. The two HTTP
  subrequest routes that used to serve them existed only for the retired
  Caddy sidecar's rewrite + forward_auth.
  """

  use OrbitWeb, :controller

  alias Orbit.Auth.Scope
  alias Orbit.GUI
  alias Orbit.Instances.Instance

  def open(conn, %{"instance_id" => raw_id} = params) do
    user = conn.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         %Instance{} = inst <- Scope.get_instance(id, user),
         :ok <- GUI.openable(inst) do
      url = GUI.open_flow(inst, params["path"])

      Orbit.Audit.write(
        action: "agent.gui_open",
        result: "ok",
        user_id: user.id,
        target_type: "instance",
        target_id: id,
        source_ip: client_ip(conn)
      )

      json(conn, %{url: url})
    else
      {:error, :disabled} ->
        conn |> put_status(404) |> json(%{detail: "gui proxy disabled"})

      {:error, :no_webif} ->
        conn |> put_status(400) |> json(%{detail: "this device type has no web ui"})

      {:error, :not_connected} ->
        conn |> put_status(503) |> json(%{detail: "agent not connected"})

      # missing / out-of-scope → 404 (no oracle).
      _ ->
        conn |> put_status(404) |> json(%{detail: "not found"})
    end
  end

  defp client_ip(conn), do: Orbit.Net.client_ip(conn)
end
