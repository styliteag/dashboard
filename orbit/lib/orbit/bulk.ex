defmodule Orbit.Bulk do
  @moduledoc """
  Bulk actions across multiple instances — port of the agent-mode arm of
  bulk/routes.py. Caller-supplied ids outside the user's groups are
  SILENTLY dropped by the scope filter: never acted on, never confirmed to
  exist (invariant 1, no existence oracle).

  Direct-poll instances answer a refusal for now — the orbit poller has no
  firmware/reboot client yet; the fleet is agent-mode. Every per-instance
  outcome is audited as `bulk.<action>` ok/error.

  Test seams (house style): `opts[:hub]`, `opts[:audit]`, `opts[:list]`
  (the visible-instances source, default `Instances.list_visible/1`).
  """

  alias Orbit.Audit
  alias Orbit.Hub
  alias Orbit.Instances
  alias Orbit.Instances.Instance

  # action name → {agent command, wait timeout ms}. firmware.check runs a
  # full repo sync on the box (90s, same as the single-instance route); the
  # others spawn a background process and return quickly.
  @agent_commands %{
    "firmware_check" => {"firmware.check", 90_000},
    "firmware_update" => {"firmware.update", 30_000},
    "firmware_upgrade" => {"firmware.upgrade", 60_000},
    "ipsec_restart" => {"ipsec.restart", 30_000},
    "reboot" => {"reboot", 30_000}
  }

  @max_concurrency 16

  def actions, do: Map.keys(@agent_commands)

  @type result :: %{
          instance_id: integer(),
          instance_name: String.t(),
          success: boolean(),
          message: String.t()
        }

  @spec run([integer()], String.t(), struct(), keyword()) ::
          {:ok, [result()]} | {:error, :unknown_action}
  def run(instance_ids, action, user, opts \\ []) do
    if Map.has_key?(@agent_commands, action) do
      ids = MapSet.new(instance_ids)
      list = Keyword.get(opts, :list, &Instances.list_visible/1)

      results =
        user
        |> list.()
        |> Enum.filter(&MapSet.member?(ids, &1.id))
        |> Task.async_stream(&run_one(&1, action, opts),
          max_concurrency: @max_concurrency,
          # Above the longest command timeout so a slow box answers its own
          # timeout message instead of killing the task.
          timeout: 100_000,
          on_timeout: :kill_task
        )
        |> Enum.map(fn
          {:ok, result} -> result
          {:exit, _} -> nil
        end)
        |> Enum.reject(&is_nil/1)

      Enum.each(results, &audit(opts, user, action, &1))
      {:ok, results}
    else
      {:error, :unknown_action}
    end
  end

  defp run_one(inst, action, opts) do
    cond do
      action in ["firmware_update", "firmware_upgrade"] and inst.firmware_locked ->
        result(inst, false, "firmware updates are locked for this instance")

      action == "firmware_upgrade" and not Instance.agent_mode?(inst) ->
        # Mirrors the single-instance route: the series upgrade needs the
        # agent to resolve the target on-box and snapshot first.
        result(inst, false, "series upgrade requires agent mode; use the vendor gui")

      not Instance.agent_mode?(inst) ->
        result(inst, false, "direct-poll bulk actions are not ported to orbit yet")

      true ->
        run_agent(inst, action, opts)
    end
  end

  defp run_agent(inst, action, opts) do
    hub = Keyword.get(opts, :hub, Hub)
    {command, timeout_ms} = @agent_commands[action]

    case Hub.send_command_on(hub, inst.id, command, %{}, timeout_ms) do
      {:error, :not_connected} ->
        result(inst, false, "agent not connected")

      raw ->
        result(inst, raw["success"] == true, String.slice(to_string(raw["output"] || ""), 0, 200))
    end
  end

  defp result(inst, success, message) do
    %{instance_id: inst.id, instance_name: inst.name, success: success, message: message}
  end

  defp audit(opts, user, action, r) do
    sink = Keyword.get(opts, :audit, &Audit.write/1)

    sink.(
      action: "bulk.#{action}",
      result: if(r.success, do: "ok", else: "error"),
      user_id: user.id,
      target_type: "instance",
      target_id: r.instance_id,
      detail: %{message: r.message}
    )
  end
end
