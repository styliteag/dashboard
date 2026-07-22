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
         {:ok, params} <-
           Orbit.Agent.Package.update_params(Orbit.Agent.Package.line_for(inst.device_type)) do
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

  # Bootstrap file downloads (update.py parity, unauthenticated). Only ever
  # serves the fixed files below out of the read-only AGENT_DIR mount —
  # no path input from the request reaches the filesystem.
  # script_linux serves the Linux agent line (§28) but keeps the download
  # filename orbit_agent.py: on the box it is a drop-in at the same path,
  # so run-agent.sh and the systemd unit stay untouched.
  @downloads %{
    script: {"orbit_agent.py", "text/x-python", "orbit_agent.py"},
    script_linux: {"orbit_agent_linux.py", "text/x-python", "orbit_agent.py"},
    rc: {"rc.d/orbit_agent", "text/plain", "orbit_agent"},
    run: {"run-agent.sh", "text/plain", "run-agent.sh"},
    systemd: {"systemd/orbit-agent.service", "text/plain", "orbit-agent.service"},
    checkmk: {"vendor/check_mk_agent.linux", "text/plain", "check_mk_agent.linux"}
  }

  def download_script(conn, _params), do: serve_agent_file(conn, :script)
  def download_script_linux(conn, _params), do: serve_agent_file(conn, :script_linux)
  def download_rc(conn, _params), do: serve_agent_file(conn, :rc)
  def download_run(conn, _params), do: serve_agent_file(conn, :run)
  def download_systemd(conn, _params), do: serve_agent_file(conn, :systemd)
  def download_checkmk(conn, _params), do: serve_agent_file(conn, :checkmk)

  defp serve_agent_file(conn, key) do
    {rel, content_type, filename} = Map.fetch!(@downloads, key)
    path = Path.join(Orbit.Agent.Package.agent_dir(), rel)

    if File.exists?(path) do
      conn
      |> put_resp_content_type(content_type)
      |> put_resp_header("content-disposition", ~s(attachment; filename="#{filename}"))
      |> send_file(200, path)
    else
      conn |> put_status(404) |> json(%{detail: "#{filename} not available"})
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
