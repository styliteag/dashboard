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

  import Ecto.Query

  alias Orbit.Instances.Instance
  alias Orbit.Repo

  def connect(conn, _params) do
    upgrade_arg =
      case bearer_token(conn) do
        nil ->
          %{auth_error: {4001, "missing token"}}

        token ->
          case instance_for_token(token) do
            %Instance{} = instance -> %{instance: instance}
            nil -> %{auth_error: {4003, "invalid token"}}
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

  # Token → live push-mode instance (ws.py:101-109 parity).
  defp instance_for_token(token) do
    Repo.one(
      from(i in Instance,
        where: i.agent_token == ^token and i.transport == "push" and is_nil(i.deleted_at)
      )
    )
  end
end
