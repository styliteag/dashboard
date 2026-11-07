defmodule OrbitWeb.ExtensionHooksAuthTest do
  @moduledoc """
  Auth extension points (docs/extension-points.md): `:session_validators`
  (HTTP request, LiveView mount, client-WebSocket upgrade) and
  `:logout_redirects`. async: false — the hooks are global app env.
  """

  use OrbitWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import OrbitWeb.TestHooks

  alias OrbitWeb.TestHooks.{LogoutRedirect, SessionValidator}
  alias OrbitWeb.{UserAuth, WSAuth}

  setup do
    %{user: user!("admin", false)}
  end

  describe ":session_validators" do
    test "unset: a normal session authenticates everywhere", %{conn: conn, user: user} do
      delete_hook(:session_validators)
      conn = login(conn, user, %{test_session_revoked: true})

      assert get(conn, ~p"/password").status == 200
      assert {:ok, _view, _html} = live(conn, ~p"/apikeys")
      assert {:ok, %{id: id}} = WSAuth.authenticate(conn)
      assert id == user.id
    end

    test "every validator must accept: a rejected session is logged out", %{
      conn: conn,
      user: user
    } do
      put_hook(:session_validators, [SessionValidator])
      revoked = login(conn, user, %{test_session_revoked: true})

      assert redirected_to(get(revoked, ~p"/password")) == ~p"/login"
      assert {:error, {:redirect, %{to: "/login"}}} = live(revoked, ~p"/apikeys")
      assert {:error, 4401} = WSAuth.authenticate(revoked)
    end

    test "an accepting validator keeps the session", %{conn: conn, user: user} do
      put_hook(:session_validators, [SessionValidator])
      conn = login(conn, user)

      assert get(conn, ~p"/password").status == 200
      assert {:ok, _view, _html} = live(conn, ~p"/apikeys")
      assert {:ok, _user} = WSAuth.authenticate(conn)
    end

    test "user_from_session/1 applies the built-in checks", %{user: user} do
      session = %{
        "user_id" => user.id,
        "password_version" => user.password_version,
        "mfa_passed" => true
      }

      assert %{id: id} = UserAuth.user_from_session(session)
      assert id == user.id
      assert UserAuth.user_from_session(%{session | "mfa_passed" => false}) == nil
      assert UserAuth.user_from_session(%{session | "password_version" => -1}) == nil
    end
  end

  describe ":logout_redirects" do
    test "unset: logout lands on /login", %{conn: conn, user: user} do
      delete_hook(:logout_redirects)
      conn = login(conn, user, %{test_logout_url: "https://idp.example.com/logout"})

      assert redirected_to(post(conn, ~p"/logout")) == ~p"/login"
    end

    test "the first URL wins; it is read before the session is dropped", %{
      conn: conn,
      user: user
    } do
      put_hook(:logout_redirects, [LogoutRedirect])
      conn = login(conn, user, %{test_logout_url: "https://idp.example.com/logout"})

      resp = post(conn, ~p"/logout")
      assert redirected_to(resp) == "https://idp.example.com/logout"
      assert get_session(resp, :user_id) == nil
    end

    test "every module answering nil falls back to /login", %{conn: conn, user: user} do
      put_hook(:logout_redirects, [LogoutRedirect])
      conn = login(conn, user)

      assert redirected_to(post(conn, ~p"/logout")) == ~p"/login"
    end
  end
end
