defmodule OrbitWeb.EnrollController do
  @moduledoc """
  Agent enrollment endpoints (§16), mirror of agent_hub/routes/enroll.py:

  - `create_code` — session + write role + instance scope; mints a one-time
    code (404 for missing/out-of-scope, no oracle).
  - `enroll` — PUBLIC, unauthenticated attack surface: rate-limited per IP
    with the login limiter, code consumed on success, 401 for
    invalid/expired (no distinction — no code-state oracle).

  Audit lands with the audit port (M6); structured-logged until then.
  """

  use OrbitWeb, :controller

  require Logger

  alias Orbit.Auth.LoginLimiter
  alias Orbit.Auth.Scope
  alias Orbit.Enrollment
  alias Orbit.Instances.Instance

  def create_code(conn, %{"instance_id" => raw_id}) do
    user = conn.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         %Instance{} <- Scope.get_instance(id, user) do
      {code, expires_at} = Enrollment.create_code(id)
      Logger.info("agent.enroll_code instance_id=#{id} user_id=#{user.id}")

      json(conn, %{code: code, instance_id: id, expires_at: DateTime.to_iso8601(expires_at)})
    else
      _ -> conn |> put_status(404) |> json(%{detail: "not found"})
    end
  end

  def enroll(conn, %{"code" => code}) when is_binary(code) do
    ip = client_ip(conn)

    cond do
      LoginLimiter.locked?(ip) ->
        conn |> put_status(429) |> json(%{detail: "too many attempts; try again later"})

      true ->
        case Enrollment.redeem(code) do
          {:ok, token, instance_id} ->
            LoginLimiter.record_success(ip)
            Logger.info("agent.enroll ok instance_id=#{instance_id}")
            json(conn, %{agent_token: token, instance_id: instance_id})

          {:error, _reason} ->
            LoginLimiter.record_failure(ip)
            # invalid and expired share one message — no code-state oracle.
            conn |> put_status(401) |> json(%{detail: "invalid or expired code"})
        end
    end
  end

  def enroll(conn, _params),
    do: conn |> put_status(422) |> json(%{detail: "code required"})

  defp client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
end
