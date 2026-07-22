defmodule Orbit.Agent.Update do
  @moduledoc """
  Push a signed agent self-update to one connected box (update.py relay
  half). Shared by the instance-detail canary button and the instances-list
  "Update all agents" banner — one place owns the version no-op, the
  pin_update_result bookkeeping and the audit write.
  """

  alias Orbit.Audit
  alias Orbit.Hub

  @doc """
  Push the served agent package to `inst`. `{:ok, msg} | {:error, msg}`.
  Pushing the already-running version is a polite no-op — the agent's
  anti-rollback would refuse it anyway.
  """
  def push(inst, user) do
    line = Orbit.Agent.Package.line_for(inst.device_type)

    with %Hub.Agent{} = agent <- Hub.get(inst.id),
         {:ok, params} <- Orbit.Agent.Package.update_params(line) do
      if agent.agent_version == params["version"] do
        {:ok, "already at #{params["version"]}"}
      else
        result = Hub.send_command(inst.id, "agent.update", params, 30_000)

        result =
          if is_map(result), do: result, else: %{"success" => false, "output" => "no agent"}

        Hub.pin_update_result(inst.id, result, params["version"])

        Audit.write(
          action: "agent.update",
          result: if(result["success"], do: "ok", else: "error"),
          user_id: user.id,
          target_type: "instance",
          target_id: inst.id,
          detail: %{"version" => params["version"]}
        )

        if result["success"] do
          {:ok, "update to #{params["version"]} pushed — agent restarts"}
        else
          {:error, String.slice(to_string(result["output"] || "update failed"), 0, 200)}
        end
      end
    else
      nil -> {:error, "agent not connected"}
      {:error, :unavailable} -> {:error, "agent script not available"}
    end
  end
end
