defmodule OrbitWeb.ShellWSController do
  @moduledoc """
  HTTP→WebSocket upgrade for `/api/ws/shell/{instance_id}` with the exact
  authorization order of the python shell route (CLAUDE.md invariant 2,
  regression b622b6f): feature gate FIRST (never hint the capability exists
  when off), then session auth, then instance scope, then per-instance
  opt-in, then hand off — the slot cap is the socket's last gate.

  Every failure upgrades and closes with the matching code so the frontend
  maps 4401/4403/4404/4008 to readable text (accept-then-close parity).
  """

  use OrbitWeb, :controller

  alias Orbit.Auth.Scope
  alias Orbit.Instances.Instance
  alias OrbitWeb.WSAuth

  def connect(conn, %{"instance_id" => raw_id}) do
    arg = authorize(conn, raw_id)

    conn
    |> WebSockAdapter.upgrade(OrbitWeb.ShellSocket, arg, timeout: 8 * 60 * 60 * 1000)
    |> halt()
  end

  defp authorize(conn, raw_id) do
    with :ok <- feature_gate(),
         {:ok, user} <- WSAuth.authenticate(conn, write: true),
         {id, ""} <- Integer.parse(raw_id),
         %Instance{} = inst <- Scope.get_instance(id, user),
         :ok <- opt_in(inst),
         {:ok, transport} <- transport(inst) do
      # Opening a root PTY on a customer firewall is the most privileged
      # thing this dashboard can do; it left no trace at all until now. The
      # snapshot-capture path was audited, the interactive ones were not.
      audit_open(conn, "shell.open", "ok", user.id, id, %{"kind" => to_string(transport)})
      %{instance_id: id, user_id: user.id, transport: transport}
    else
      {:error, code} ->
        audit_denied(conn, raw_id, code)
        %{auth_error: code}

      # out-of-scope / missing instance / not push-connected: 4403 like the
      # python shell route (get_instance None → close 4403).
      _ ->
        audit_denied(conn, raw_id, 4403)
        %{auth_error: 4403}
    end
  end

  # Refusals are audited too (CLAUDE.md: audit denied/error paths). The user
  # may be unknown at this point — an unauthenticated attempt still belongs
  # in the trail, keyed by source IP.
  defp audit_denied(conn, raw_id, code) do
    # The session may not have resolved (that can be the very reason for the
    # refusal) — nil user_id is fine, the source IP carries the trail.
    user_id = conn.assigns[:current_user] && conn.assigns.current_user.id

    audit_open(conn, "shell.open", "denied", user_id, parse_id(raw_id), %{
      "reason" => "close_#{code}"
    })
  end

  defp audit_open(conn, action, result, user_id, instance_id, detail) do
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

  defp parse_id(raw) do
    case Integer.parse(to_string(raw)) do
      {id, ""} -> id
      _ -> nil
    end
  end

  # Feature gate first (§22): OFF ⇒ 4403, never reveal the capability exists.
  defp feature_gate do
    if System.get_env("DASH_SHELL_ENABLED", "false") in ~w(true 1 yes on),
      do: :ok,
      else: {:error, 4403}
  end

  # Per-instance opt-in on top of the global gate (Edit instance → Terminal).
  defp opt_in(%Instance{shell_enabled: true}), do: :ok
  defp opt_in(%Instance{}), do: {:error, 4403}

  # LAST gate, and the only transport-aware one: everything above (feature gate,
  # session, scope, per-instance opt-in) is identical for both paths.
  #
  # A push box attaches to its agent's PTY. A Securepoint has no agent and never
  # will, so it uses the same SSH access the swanctl enrichment uses — which
  # means it needs a pinned host key, because that transport is fail-closed.
  # Anything else is 4404 ("no box to attach to"), unchanged.
  defp transport(%Instance{id: id} = inst) do
    cond do
      Orbit.Hub.get(id) -> {:ok, :agent}
      ssh_shell_possible?(inst) -> {:ok, :ssh}
      true -> {:error, 4404}
    end
  end

  @doc false
  def ssh_shell_possible?(%Instance{device_type: "securepoint", ssh_enabled: true} = inst) do
    present?(inst.ssh_key_enc) and present?(inst.ssh_host_key)
  end

  def ssh_shell_possible?(%Instance{}), do: false

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: true
end
