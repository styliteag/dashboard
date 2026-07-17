defmodule Orbit.Firmware do
  @moduledoc """
  Firmware orchestration over the agent hub — port of the agent-mode arm of
  backend/src/app/firmware/routes.py (direct-poll instances stay a python
  surface until the poller port grows firmware endpoints).

  - `check/3` — firmware.check on the box (90s); the verdict is merged into
    the hub's firmware section (`Hub.set_firmware`) so all four check
    surfaces update without waiting for the next push. Merge semantics:
    keys the agent didn't report keep their cached value (a manual check
    never blanks `security_updates` from the last push).
  - `update/3` — routine package update; refused while `firmware_locked`.
  - `upgrade/3` — vendor series/major upgrade. Agent mode only: the agent
    resolves the target from the box's own unlocked upgrade path (a
    caller-supplied target is deliberately not honored) and creates a ZFS
    boot environment first. The action string lives in the internal-actions
    set on both hubs, so the generic command passthrough rejects it.
  - `upgrade_status/2` — running/done + log tail for live tracking; agents
    predating the command (or a reply timeout) degrade to "unknown".

  Started actions are audited ok/error. A locked / not-connected refusal
  happens before any command and writes no audit row (python parity: the
  HTTP layer answered 409/503 without one).

  Test seams (house style — DB-free tests, injected state): `opts[:hub]`
  targets a private hub instance, `opts[:audit]` replaces the audit sink.
  """

  alias Orbit.Audit
  alias Orbit.Hub
  alias Orbit.Instances.Instance

  @check_timeout_ms 90_000
  @update_timeout_ms 30_000
  @upgrade_timeout_ms 60_000
  @status_timeout_ms 15_000

  @type action_result :: {:ok, String.t()} | {:error, :locked | :not_connected | String.t()}

  @spec check(Instance.t(), map() | struct(), keyword()) :: action_result()
  def check(inst, user, opts \\ []) do
    hub = Keyword.get(opts, :hub, Hub)

    case Hub.send_command_on(hub, inst.id, "firmware.check", %{}, @check_timeout_ms) do
      {:error, :not_connected} ->
        {:error, :not_connected}

      result ->
        output = to_string(result["output"] || "")
        Hub.set_firmware(hub, inst.id, verdict_fields(result, output))
        # The check RAN — a "no updates" or even check_failed outcome is an ok
        # audit; the failure lands in the cached verdict (python parity).
        audit(opts, inst, user, "firmware.check", "ok", nil)
        {:ok, truncate(output, 200, "check complete")}
    end
  end

  @spec update(Instance.t(), map() | struct(), keyword()) :: action_result()
  def update(inst, user, opts \\ []) do
    if inst.firmware_locked do
      {:error, :locked}
    else
      run_start(inst, user, "firmware.update", @update_timeout_ms, opts)
    end
  end

  @spec upgrade(Instance.t(), map() | struct(), keyword()) :: action_result()
  def upgrade(inst, user, opts \\ []) do
    cond do
      inst.firmware_locked -> {:error, :locked}
      not Instance.agent_mode?(inst) -> {:error, "series upgrade requires agent mode"}
      true -> run_start(inst, user, "firmware.upgrade", @upgrade_timeout_ms, opts)
    end
  end

  @doc """
  Poll upgrade/update progress on the box. Always answers a map — tracking
  UIs treat "unknown" as "keep waiting, stop after a grace period".
  """
  @spec upgrade_status(Instance.t(), keyword()) :: %{status: String.t(), log: [String.t()]}
  def upgrade_status(inst, opts \\ []) do
    hub = Keyword.get(opts, :hub, Hub)

    case Hub.send_command_on(hub, inst.id, "firmware.upgrade_status", %{}, @status_timeout_ms) do
      {:error, :not_connected} ->
        %{status: "unknown", log: []}

      result ->
        if result["success"] && result["status"] in ["running", "done"] do
          %{status: result["status"], log: Enum.map(result["log"] || [], &to_string/1)}
        else
          %{status: "unknown", log: []}
        end
    end
  end

  defp run_start(inst, user, action, timeout_ms, opts) do
    hub = Keyword.get(opts, :hub, Hub)

    case Hub.send_command_on(hub, inst.id, action, %{}, timeout_ms) do
      {:error, :not_connected} ->
        {:error, :not_connected}

      result ->
        success = result["success"] == true
        output = truncate(to_string(result["output"] || ""), 200, "")
        audit(opts, inst, user, action, if(success, do: "ok", else: "error"), %{message: output})

        if success do
          {:ok, output}
        else
          {:error, if(output == "", do: "#{action} failed", else: output)}
        end
    end
  end

  # Only keys the command actually reported land in the merge; version fields
  # the agent omitted keep their cached values (Hub.set_firmware merge).
  defp verdict_fields(result, output) do
    upgrade_available = upgrade_available?(result, output)

    base = %{
      "upgrade_available" => upgrade_available,
      "check_failed" => result["check_failed"] == true,
      "updates_available" => if(upgrade_available, do: 1, else: 0),
      "status_msg" => truncate(output, 500, ""),
      "last_check" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    ~w(product_version branch known_branches product_latest upgrade_major_version)
    |> Enum.reduce(base, fn key, acc ->
      case result[key] do
        v when v in [nil, "", []] -> acc
        v -> Map.put(acc, key, v)
      end
    end)
  end

  # Newer agents report the verdict explicitly; older ones only the output
  # text (routes.py heuristic, kept verbatim).
  defp upgrade_available?(result, output) do
    case result["upgrade_available"] do
      nil ->
        low = String.downcase(output)
        String.contains?(low, "can be updated") or String.contains?(low, "updates available")

      value ->
        value == true
    end
  end

  defp truncate(text, max, empty_fallback) do
    case String.slice(text, 0, max) do
      "" -> empty_fallback
      cut -> cut
    end
  end

  defp audit(opts, inst, user, action, result, detail) do
    sink = Keyword.get(opts, :audit, &Audit.write/1)

    sink.(
      action: action,
      result: result,
      user_id: user.id,
      target_type: "instance",
      target_id: inst.id,
      detail: detail
    )
  end
end
