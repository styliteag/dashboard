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

  alias Orbit.Accounts
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
      [] -> :ok
      [origin | _] -> if origin_allowed?(origin), do: :ok, else: {:error, 4403}
    end
  end

  # Reject a cross-site WS handshake (hub.py _ws_origin_ok). No Origin
  # (non-browser) passes; localhost/127.0.0.1 always pass (dev).
  defp origin_allowed?(origin) do
    host = origin |> URI.parse() |> Map.get(:host) |> to_string() |> String.downcase()

    cond do
      host in ~w(localhost 127.0.0.1 ::1) -> true
      host == "" -> true
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

  defp check_session(conn) do
    user_id = get_session(conn, :user_id)
    pwv = get_session(conn, :password_version)
    mfa = get_session(conn, :mfa_passed)

    with true <- is_integer(user_id) and not is_nil(pwv) and mfa == true,
         %User{} = user <- Accounts.get_user(user_id),
         true <- user.password_version == pwv and not user.disabled do
      {:ok, user}
    else
      _ -> {:error, 4401}
    end
  end

  defp check_write(_user, false), do: :ok
  defp check_write(%User{role: role}, true) when role in @write_roles, do: :ok
  defp check_write(_user, true), do: {:error, 4403}
end
