defmodule Orbit.Monitors do
  @moduledoc """
  Ping monitors, both families (ipsec/ping_service.py + connectivity/
  service.py port):

  - **IPsec Phase-2 monitors** (`ipsec_ping_monitors`) — a (source,
    destination) probe per child SA, keyed by the swanctl child name.
  - **Standalone connectivity monitors** (`connectivity_monitors`) — a
    named probe not tied to any tunnel; the agent echoes the row id so the
    `connectivity:<id>` check key stays stable across renames.

  The agent's monitor sets start EMPTY and are only populated by a
  config_update — the socket re-pushes both sets right after every welcome
  (see OrbitWeb.AgentSocket), and every mutation here pushes immediately.
  Agent-mode only; a direct-poll instance has no agent to ping from.
  """

  require Logger

  alias Orbit.Hub

  # ---- standalone connectivity monitors ------------------------------------

  def list_connectivity(instance_id) do
    Orbit.Repo.query!(
      "SELECT id, name, source, destination, enabled, ping_count " <>
        "FROM connectivity_monitors WHERE instance_id = ? ORDER BY name",
      [instance_id]
    ).rows
    |> Enum.map(fn [id, name, source, destination, enabled, ping_count] ->
      %{
        id: id,
        name: name,
        source: source,
        destination: destination,
        enabled: enabled == 1 or enabled == true,
        ping_count: ping_count
      }
    end)
  rescue
    _ -> []
  catch
    # A pool checkout exits rather than raising; same empty fallback, or the
    # page that only wanted a monitor list goes down with the database.
    _kind, _reason -> []
  end

  @doc "Create a standalone monitor. {:ok, id} | {:error, msg}."
  def create_connectivity(instance_id, attrs) do
    with {:ok, name, destination} <- validate_conn(attrs) do
      Orbit.Repo.query!(
        "INSERT INTO connectivity_monitors " <>
          "(instance_id, name, source, destination, enabled, ping_count, created_at, updated_at) " <>
          "VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())",
        [
          instance_id,
          name,
          String.trim(attrs["source"] || ""),
          destination,
          true,
          ping_count(attrs)
        ]
      )

      push_to_agent(instance_id)
      :ok
    end
  rescue
    e in MyXQL.Error ->
      if e.mysql && e.mysql.code == 1062,
        do: {:error, "a monitor with this name already exists"},
        else: {:error, "save failed"}
  end

  @doc """
  Edit an existing connectivity monitor (name, source, destination, count,
  enabled).

  Was missing entirely: the UI could only create and delete, so changing a
  destination meant deleting the monitor and losing its history and its
  `connectivity:<id>` check key with it.
  """
  def update_connectivity(instance_id, monitor_id, attrs) do
    with {:ok, name, destination} <- validate_conn(attrs) do
      Orbit.Repo.query!(
        "UPDATE connectivity_monitors SET name = ?, source = ?, destination = ?, " <>
          "ping_count = ?, enabled = ?, updated_at = NOW() WHERE id = ? AND instance_id = ?",
        [
          name,
          String.trim(attrs["source"] || ""),
          destination,
          ping_count(attrs),
          attrs["enabled"] in ["true", "on", "1", true],
          monitor_id,
          instance_id
        ]
      )

      push_to_agent(instance_id)
      :ok
    end
  rescue
    e in MyXQL.Error ->
      if e.mysql && e.mysql.code == 1062,
        do: {:error, "a monitor with this name already exists"},
        else: {:error, "save failed"}
  end

  def toggle_connectivity(instance_id, monitor_id) do
    Orbit.Repo.query!(
      "UPDATE connectivity_monitors SET enabled = NOT enabled, updated_at = NOW() " <>
        "WHERE id = ? AND instance_id = ?",
      [monitor_id, instance_id]
    )

    push_to_agent(instance_id)
    :ok
  end

  def delete_connectivity(instance_id, monitor_id) do
    Orbit.Repo.query!(
      "DELETE FROM connectivity_monitors WHERE id = ? AND instance_id = ?",
      [monitor_id, instance_id]
    )

    push_to_agent(instance_id)
    :ok
  end

  defp validate_conn(attrs) do
    name = String.trim(attrs["name"] || "")
    destination = String.trim(attrs["destination"] || "")

    cond do
      name == "" -> {:error, "name is required"}
      destination == "" -> {:error, "destination is required"}
      true -> {:ok, name, destination}
    end
  end

  defp ping_count(attrs) do
    case Integer.parse(to_string(attrs["ping_count"] || "3")) do
      {n, ""} when n in 1..20 -> n
      _ -> 3
    end
  end

  # ---- ipsec phase-2 monitors -----------------------------------------------

  def list_ipsec(instance_id) do
    Orbit.Repo.query!(
      "SELECT id, tunnel_id, child_name, local_ts, remote_ts, source, destination, " <>
        "enabled, ping_count FROM ipsec_ping_monitors WHERE instance_id = ? ORDER BY child_name",
      [instance_id]
    ).rows
    |> Enum.map(fn [id, tunnel_id, child, lts, rts, src, dst, enabled, count] ->
      %{
        id: id,
        tunnel_id: tunnel_id,
        child_name: child,
        local_ts: lts,
        remote_ts: rts,
        source: src,
        destination: dst,
        enabled: enabled == 1 or enabled == true,
        ping_count: count
      }
    end)
  rescue
    _ -> []
  catch
    # A pool checkout exits rather than raising; same empty fallback, or the
    # page that only wanted a monitor list goes down with the database.
    _kind, _reason -> []
  end

  @doc """
  Create a Phase-2 ping monitor (one per child SA — the unique key mirrors
  the python 409). {:ok | {:error, msg}}; pushes the set on success.
  """
  def create_ipsec(instance_id, attrs) do
    destination = String.trim(attrs["destination"] || "")

    cond do
      String.trim(attrs["child_name"] || "") == "" ->
        {:error, "child name is required"}

      destination == "" ->
        {:error, "destination is required"}

      true ->
        Orbit.Repo.query!(
          "INSERT INTO ipsec_ping_monitors " <>
            "(instance_id, tunnel_id, child_name, local_ts, remote_ts, source, destination, " <>
            "enabled, ping_count, created_at, updated_at) " <>
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
          [
            instance_id,
            String.trim(attrs["tunnel_id"] || ""),
            String.trim(attrs["child_name"] || ""),
            attrs["local_ts"] || "",
            attrs["remote_ts"] || "",
            String.trim(attrs["source"] || ""),
            destination,
            true,
            ping_count(attrs)
          ]
        )

        push_to_agent(instance_id)
        :ok
    end
  rescue
    e in MyXQL.Error ->
      if e.mysql && e.mysql.code == 1062,
        do: {:error, "a ping monitor for this Phase 2 already exists"},
        else: {:error, "save failed"}
  end

  @doc "Update an existing Phase-2 monitor (source/destination/count/enabled)."
  def update_ipsec(instance_id, monitor_id, attrs) do
    destination = String.trim(attrs["destination"] || "")

    if destination == "" do
      {:error, "destination is required"}
    else
      Orbit.Repo.query!(
        "UPDATE ipsec_ping_monitors SET source = ?, destination = ?, ping_count = ?, " <>
          "enabled = ?, updated_at = NOW() WHERE id = ? AND instance_id = ?",
        [
          String.trim(attrs["source"] || ""),
          destination,
          ping_count(attrs),
          attrs["enabled"] in ["true", "on", "1", true],
          monitor_id,
          instance_id
        ]
      )

      push_to_agent(instance_id)
      :ok
    end
  end

  def delete_ipsec(instance_id, monitor_id) do
    Orbit.Repo.query!(
      "DELETE FROM ipsec_ping_monitors WHERE id = ? AND instance_id = ?",
      [monitor_id, instance_id]
    )

    push_to_agent(instance_id)
    :ok
  end

  @doc "Phase-2 monitors for MANY instances at once (fleet VPN view): %{instance_id => [monitor]}."
  def list_ipsec_for(instance_ids) when is_list(instance_ids) do
    case instance_ids do
      [] ->
        %{}

      ids ->
        placeholders = Enum.map_join(ids, ", ", fn _ -> "?" end)

        Orbit.Repo.query!(
          "SELECT instance_id, id, tunnel_id, child_name, local_ts, remote_ts, source, " <>
            "destination, enabled, ping_count FROM ipsec_ping_monitors " <>
            "WHERE instance_id IN (#{placeholders}) ORDER BY child_name",
          ids
        ).rows
        |> Enum.group_by(&hd/1, fn [iid, id, tunnel_id, child, lts, rts, src, dst, enabled, count] ->
          %{
            instance_id: iid,
            id: id,
            tunnel_id: tunnel_id,
            child_name: child,
            local_ts: lts,
            remote_ts: rts,
            source: src,
            destination: dst,
            enabled: enabled == 1 or enabled == true,
            ping_count: count
          }
        end)
    end
  rescue
    _ -> %{}
  catch
    _kind, _reason -> %{}
  end

  # ---- agent config push -----------------------------------------------------

  @doc """
  Serialize both families into the agent's config_update shape (pure).
  Connectivity rows include `id` (the agent echoes it per result); ipsec
  rows are keyed by child_name.
  """
  def config_payload(ipsec_monitors, connectivity_monitors) do
    %{
      "ipsec_ping_monitors" =>
        for m <- ipsec_monitors do
          %{
            "tunnel_id" => m.tunnel_id,
            "child_name" => m.child_name,
            "local_ts" => m.local_ts,
            "remote_ts" => m.remote_ts,
            "source" => m.source,
            "destination" => m.destination,
            "enabled" => m.enabled,
            "ping_count" => m.ping_count
          }
        end,
      "connectivity_monitors" =>
        for m <- connectivity_monitors do
          %{
            "id" => m.id,
            "name" => m.name,
            "source" => m.source,
            "destination" => m.destination,
            "enabled" => m.enabled,
            "ping_count" => m.ping_count
          }
        end
    }
  end

  @doc """
  Run ONE ping right now against the values in the editor, whichever way this
  box can be reached — the dialog's "Test" button.

  An agent box runs the agent's one-off `ipsec.ping_test`; a Securepoint has no
  agent and runs the same probe over SSH. Without this branch Test answered
  "no agent" on exactly the boxes whose monitors we had just made work.

  Returns `{:ok, summary}` / `{:error, summary}` — never raises, because this is
  a user-facing button and a bad source address is a normal answer, not a crash.
  """
  def ping_test(inst, source, destination, count) do
    cond do
      Orbit.Instances.Instance.agent_mode?(inst) ->
        agent_ping_test(inst, source, destination, count)

      Orbit.Instances.Instance.monitors_runnable?(inst) ->
        ssh_ping_test(inst, source, destination, count)

      true ->
        {:error, "this box cannot run pings — no agent, and SSH is not configured"}
    end
  end

  defp agent_ping_test(inst, source, destination, count) do
    payload = %{
      "source" => String.trim(to_string(source)),
      "destination" => String.trim(to_string(destination)),
      "ping_count" => to_string(count)
    }

    case Hub.send_command(inst.id, "ipsec.ping_test", payload, 20_000) do
      %{"success" => true} = r -> {:ok, r["output"] || "ok"}
      %{"output" => out} -> {:error, out || "ping failed"}
      _ -> {:error, "agent not connected"}
    end
  end

  defp ssh_ping_test(inst, source, destination, count) do
    with {:ok, cfg} <- Orbit.Securepoint.SSH.config_for(inst) do
      case Orbit.Securepoint.SSH.with_connection(cfg, fn conn ->
             Orbit.Securepoint.SSH.ping(conn, source, destination, count)
           end) do
        %{"ping_state" => "ok"} = r ->
          {:ok, "reachable — #{r["ping_loss_pct"]}% loss, #{r["ping_rtt_ms"]} ms avg"}

        %{"ping_state" => "fail"} ->
          {:error, "no reply (100% loss)"}

        %{"ping_state" => "error"} ->
          {:error, "the ping could not run — check the source address"}

        {:error, reason} ->
          {:error, to_string(reason)}

        _ ->
          {:error, "ping failed"}
      end
    else
      _ -> {:error, "SSH is not configured for this box"}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  @doc """
  Push the instance's current monitor sets to its connected agent
  (best-effort; an offline agent gets them re-sent after its next hello).
  """
  def push_to_agent(instance_id) do
    Hub.send_config(
      instance_id,
      config_payload(list_ipsec(instance_id), list_connectivity(instance_id))
    )

    :ok
  rescue
    e ->
      Logger.warning("monitors.push_failed instance_id=#{instance_id} #{Exception.message(e)}")
      :ok
  end
end
