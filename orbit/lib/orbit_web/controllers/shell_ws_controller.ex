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
         :ok <- agent_present(id) do
      %{instance_id: id, user_id: user.id}
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

  # A connected agent must exist (ssh-only Securepoint path ports later).
  defp agent_present(instance_id) do
    if Orbit.Hub.get(instance_id), do: :ok, else: {:error, 4404}
  end
end
