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
      %{instance_id: id, user_id: user.id, transport: transport}
    else
      {:error, code} -> %{auth_error: code}
      # out-of-scope / missing instance / not push-connected: 4403 like the
      # python shell route (get_instance None → close 4403).
      _ -> %{auth_error: 4403}
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
