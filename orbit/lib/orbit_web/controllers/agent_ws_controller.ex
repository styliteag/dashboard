defmodule OrbitWeb.AgentWSController do
  @moduledoc """
  HTTP→WebSocket upgrade for `/api/ws/agent`.

  §27 fidelity: the python hub ACCEPTS the socket first and only then closes
  with 4001 (missing token) / 4003 (invalid token) after an error frame — so
  auth failures here still upgrade and let the socket process send the error
  frame + close code, instead of answering with an HTTP status the agent's
  reconnect loop has never seen.
  """

  use OrbitWeb, :controller

  alias Orbit.AgentBinding
  alias Orbit.Instances.Instance

  def connect(conn, _params) do
    upgrade_arg =
      case bearer_token(conn) do
        nil ->
          %{auth_error: {4001, "missing token"}}

        token ->
          case AgentBinding.instance_for_token(token) do
            %Instance{} = instance ->
              # The address the fleet reaches us from — shown as "Connects
              # from" next to the box's own public IP. Via Orbit.Net, never
              # conn.remote_ip: in prod the hub sits behind a reverse proxy,
              # so the raw peer is that proxy and every box would look identical.
              %{instance: instance, source_ip: Orbit.Net.client_ip(conn)}

            nil ->
              Orbit.Hub.bump(:auth_failures)
              %{auth_error: {4003, "invalid token"}}
          end
      end

    conn
    |> WebSockAdapter.upgrade(OrbitWeb.AgentSocket, upgrade_arg, timeout: 120_000)
    |> halt()
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token | _] when token != "" -> token
      _ -> nil
    end
  end
end
