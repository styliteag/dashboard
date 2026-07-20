defmodule OrbitWeb.CaptureWSController do
  @moduledoc """
  HTTP→WebSocket upgrade for `/api/ws/capture/:instance_id` with the capture
  auth order of hub.py capture_websocket (regression b622b6f): session auth
  with a write role, then instance scope, then a connected agent — no feature
  gate or opt-in (unlike shell). `?interface=` and `?filter=` select the
  capture. Failures upgrade then close 4401/4403/4404 (accept-then-close
  parity).

  Audit of capture.open lands with the audit port (M6); until then the open
  is structured-logged. Documented gap, not a silent omission.
  """

  use OrbitWeb, :controller

  require Logger

  alias Orbit.Auth.Scope
  alias Orbit.Instances.Instance
  alias OrbitWeb.WSAuth

  def connect(conn, %{"instance_id" => raw_id} = params) do
    arg = authorize(conn, raw_id, params)
    conn |> WebSockAdapter.upgrade(OrbitWeb.CaptureSocket, arg, timeout: 60_000) |> halt()
  end

  defp authorize(conn, raw_id, params) do
    with {:ok, user} <- WSAuth.authenticate(conn, write: true),
         {id, ""} <- Integer.parse(raw_id),
         %Instance{} = _inst <- Scope.get_instance(id, user),
         :ok <- agent_present(id) do
      Logger.info(
        "capture.open instance_id=#{id} user_id=#{user.id} interface=#{params["interface"]} filter=#{params["filter"]}"
      )

      # A live capture streams a box's raw traffic to a browser — as
      # privileged as the snapshot path, which has always been audited.
      # The interface is recorded; the BPF filter is not, since an operator
      # can put host/port details of third parties in it.
      audit(conn, "capture.open", "ok", user.id, id, %{
        "interface" => to_string(params["interface"] || "")
      })

      %{
        instance_id: id,
        interface: params["interface"] || "",
        filter: params["filter"] || ""
      }
    else
      {:error, code} ->
        audit_denied(conn, raw_id, code)
        %{auth_error: code}

      # out-of-scope / missing → 4403 (capture route parity).
      _ ->
        audit_denied(conn, raw_id, 4403)
        %{auth_error: 4403}
    end
  end

  defp audit_denied(conn, raw_id, code) do
    user_id = conn.assigns[:current_user] && conn.assigns.current_user.id
    instance_id = with {id, ""} <- Integer.parse(to_string(raw_id)), do: id, else: (_ -> nil)

    audit(conn, "capture.open", "denied", user_id, instance_id, %{"reason" => "close_#{code}"})
  end

  defp audit(conn, action, result, user_id, instance_id, detail) do
    Orbit.Audit.write(
      action: action,
      result: result,
      user_id: user_id,
      target_type: "instance",
      target_id: instance_id,
      source_ip: Orbit.Net.client_ip(conn),
      detail: detail
    )
  end

  defp agent_present(instance_id) do
    if Orbit.Hub.get(instance_id), do: :ok, else: {:error, 4404}
  end
end
