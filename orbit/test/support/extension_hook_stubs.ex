defmodule OrbitWeb.TestHooks do
  @moduledoc """
  Stub modules for the downstream extension points (docs/extension-points.md).
  Compile-time hooks (`:extra_forwards`, `:extra_superadmin_live`) register
  these in `config/test.exs`; runtime hooks are switched on per test with
  `put_hook/2`. Open itself registers none outside the test env.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  @doc "Set a runtime hook key for one test, restoring the previous value after."
  def put_hook(key, value) do
    prev = Application.fetch_env(:orbit, key)
    Application.put_env(:orbit, key, value)

    on_exit(fn ->
      case prev do
        {:ok, v} -> Application.put_env(:orbit, key, v)
        :error -> Application.delete_env(:orbit, key)
      end
    end)
  end

  @doc "Unset a runtime hook key for one test (the open default), restored after."
  def delete_hook(key) do
    put_hook(key, nil)
    Application.delete_env(:orbit, key)
  end

  @doc "A DB user for hook tests (`role`, superadmin flag, group memberships)."
  def user!(role, superadmin?, group_ids \\ []) do
    {:ok, user} =
      Orbit.Accounts.Admin.create_user(%{
        "username" => "hook-#{System.unique_integer([:positive])}",
        "password" => "long-enough-pw",
        "role" => role,
        "is_superadmin" => superadmin?,
        "group_ids" => group_ids
      })

    user
  end

  @doc "A conn carrying a fully authenticated session for `user` (plus `extra`)."
  def login(conn, user, extra \\ %{}) do
    Plug.Test.init_test_session(
      conn,
      Map.merge(
        %{user_id: user.id, password_version: user.password_version, mfa_passed: true},
        extra
      )
    )
  end

  defmodule ForwardPlug do
    @moduledoc "`:extra_forwards` stub: answers every request itself."
    @behaviour Plug

    import Plug.Conn

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts) do
      send_resp(conn, 200, "forwarded #{conn.method} #{conn.request_path} #{inspect(opts)}")
    end
  end

  defmodule SuperadminLive do
    @moduledoc "`:extra_superadmin_live` stub page."
    use OrbitWeb, :live_view

    @impl true
    def render(assigns) do
      ~H"""
      <p id="extra-superadmin">extra superadmin page</p>
      """
    end
  end

  defmodule Suppressor do
    @moduledoc "`:notification_suppressors` stub: drops `test:suppressed` alerts."
    def suppress?(instance_id, check_key) do
      send(self(), {:suppress?, instance_id, check_key})
      check_key == "test:suppressed"
    end
  end

  defmodule LogoutRedirect do
    @moduledoc "`:logout_redirects` stub: the URL stored in the session, if any."
    def logout_redirect(conn), do: Plug.Conn.get_session(conn, :test_logout_url)
  end

  defmodule SessionValidator do
    @moduledoc "`:session_validators` stub: rejects sessions flagged as revoked."
    def valid_session?(_user, session), do: session["test_session_revoked"] != true
  end

  defmodule Badge do
    @moduledoc "`:instance_badges` stub: a badge on instances named `badge-*`."
    def badge(%{name: "badge-" <> _}), do: %{label: "test badge", title: "set by the hook"}
    def badge(_instance), do: nil
  end
end
