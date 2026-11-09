defmodule OrbitWeb.WSAuth do
  @moduledoc """
  Shared authorization for the client-facing WebSocket routes (GUI tunnel,
  shell, capture) — the exact order and close codes of hub.py
  `_ws_authenticate` / `_ws_origin_ok` (CLAUDE.md invariant 2).

  Phoenix runs this in the controller BEFORE the socket upgrade (the session
  is only readable in the plug pipeline). The controller then upgrades and,
  on any failure, the socket closes with the returned code — so the frontend
  still maps 4401/4403/4404 to readable text, exactly like the python hub
  which accepts-then-closes.

  Returns `{:ok, user}` or `{:error, close_code}`. Close codes: 4401 unauth,
  4403 forbidden (origin / role / feature / scope), 4404 no agent.
  """

  import Plug.Conn

  alias Orbit.Accounts.User

  @write_roles ~w(admin user)

  @doc """
  Full session validation, parity with REST current_user: origin, session
  keys + passed second factor, user still valid, and (when write) a
  non-view_only role.
  """
  @spec authenticate(Plug.Conn.t(), keyword()) :: {:ok, User.t()} | {:error, 4401 | 4403}
  def authenticate(conn, opts \\ []) do
    write? = Keyword.get(opts, :write, false)

    with :ok <- check_origin(conn),
         {:ok, user} <- check_session(conn),
         :ok <- check_write(user, write?) do
      {:ok, user}
    end
  end

  defp check_origin(conn) do
    case get_req_header(conn, "origin") do
      [origin | _] -> if origin_allowed?(origin), do: :ok, else: {:error, 4403}
      [] -> {:error, 4403}
    end
  end

  # Reject a cross-site WS handshake (hub.py _ws_origin_ok). These sockets
  # (root shell, packet capture) are only opened by the dashboard page, so a
  # browser Origin is required: no header, the opaque "null" origin
  # (sandboxed iframe, file:, data:) and host-less values are refused.
  # localhost/127.0.0.1 always pass (dev).
  defp origin_allowed?(origin) do
    host = origin |> URI.parse() |> Map.get(:host) |> to_string() |> String.downcase()

    cond do
      host == "" -> false
      host in ~w(localhost 127.0.0.1 ::1) -> true
      true -> host in allowed_origin_hosts()
    end
  end

  defp allowed_origin_hosts do
    webauthn_host =
      System.get_env("DASH_WEBAUTHN_ORIGIN", "")
      |> URI.parse()
      |> Map.get(:host)
      |> to_string()
      |> String.downcase()

    extra =
      System.get_env("DASH_WS_ALLOWED_ORIGIN_HOSTS", "")
      |> String.split(",", trim: true)
      |> Enum.map(&(&1 |> String.trim() |> String.downcase()))

    [webauthn_host | extra] |> Enum.reject(&(&1 == "")) |> MapSet.new()
  end

  # Same rules as REST and LiveView (user, password version, disabled, MFA,
  # `:session_validators`), via the one shared check.
  defp check_session(conn) do
    case OrbitWeb.UserAuth.user_from_session(get_session(conn)) do
      %User{} = user -> {:ok, user}
      _ -> {:error, 4401}
    end
  end

  defp check_write(_user, false), do: :ok
  defp check_write(%User{role: role}, true) when role in @write_roles, do: :ok
  defp check_write(_user, true), do: {:error, 4403}
end
