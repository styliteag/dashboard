defmodule OrbitWeb.AgentApiController do
  @moduledoc """
  Session-authed JSON surface over the hub (first slice of the python
  management routes). Hub state is UNSCOPED in-memory data (invariant 5):
  everything here filters through the caller's scope before answering.
  """

  use OrbitWeb, :controller

  alias Orbit.Auth.Scope
  alias Orbit.Hub

  def connected(conn, _params) do
    user = conn.assigns.current_user

    visible =
      Hub.list_connected()
      |> Enum.filter(fn agent ->
        # by-id scope check per entry: hub state is unscoped memory.
        Scope.get_instance(agent.instance_id, user) != nil
      end)
      |> Enum.map(fn agent ->
        %{
          instance_id: agent.instance_id,
          agent_version: agent.agent_version,
          platform: agent.platform,
          connected_at: agent.connected_at,
          pushes: agent.pushes,
          last_push_at: agent.last_push_at
        }
      end)

    json(conn, visible)
  end

  def ping(conn, %{"instance_id" => raw_id}) do
    user = conn.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      case Hub.send_command(id, "ping", %{}, 10_000) do
        {:error, :not_connected} ->
          conn |> put_status(404) |> json(%{detail: "agent not connected"})

        result ->
          json(conn, result)
      end
    else
      # Missing and out-of-scope answer identically: 404, never 403.
      _ -> conn |> put_status(404) |> json(%{detail: "instance not found"})
    end
  end

  @doc """
  Push the container's agent code to ONE connected agent (self-update).
  Per-instance by design — the canary mechanism (DR-6): update one box,
  confirm it reconnects healthy at the new version, then the next.
  """
  def update(conn, %{"instance_id" => raw_id}) do
    user = conn.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         %Orbit.Hub.Agent{} = agent <- Hub.get(id),
         {:ok, params} <- Orbit.Agent.Package.update_params() do
      do_update(conn, id, agent, params)
    else
      {:error, :unavailable} ->
        conn |> put_status(500) |> json(%{detail: "agent script not available"})

      nil ->
        conn |> put_status(503) |> json(%{detail: "agent not connected"})

      _ ->
        conn |> put_status(404) |> json(%{detail: "instance not found"})
    end
  end

  defp do_update(conn, id, agent, params) do
    cond do
      # Pushing the served version to an agent already on it only trips the
      # agent's anti-rollback and leaves a sticky "rejected" marker — no-op.
      agent.agent_version == params["version"] ->
        json(conn, %{
          sent: false,
          version: params["version"],
          result: %{success: true, output: "already at #{params["version"]}"}
        })

      true ->
        result = Hub.send_command(id, "agent.update", params, 30_000)

        result =
          if is_map(result), do: result, else: %{"success" => false, "output" => "no agent"}

        Hub.pin_update_result(id, result, params["version"])
        json(conn, %{sent: true, version: params["version"], result: result})
    end
  end
end
