defmodule OrbitWeb.SessionEnrollTest do
  @moduledoc """
  /login/enroll against both pending kinds. Regression (MFA enroll bypass):
  the pending session did not record WHY the second factor was pending, so a
  password-only session of a user WITH a factor (pending_verify) could GET
  /login/enroll — which overwrote the real totp_secret_enc and cleared
  totp_enabled — and then POST a code from the self-minted QR to receive a
  full session. Password alone beat TOTP/passkey and destroyed the factor.
  """

  use OrbitWeb.ConnCase, async: false

  import Bitwise
  import OrbitWeb.TestHooks, only: [user!: 2]

  alias Orbit.Accounts.User
  alias Orbit.Repo

  @password "long-enough-pw"

  defp totp_user! do
    secret = Orbit.Auth.TOTP.generate_secret()

    user =
      user!("admin", false)
      |> Ecto.Changeset.change(totp_secret_enc: Orbit.Crypto.encrypt(secret), totp_enabled: true)
      |> Repo.update!()

    {user, secret}
  end

  defp reload(user), do: Repo.get!(User, user.id)

  # RFC 6238 code for `secret` now (test-side copy of TOTP's private hotp).
  defp code(secret) do
    key = Base.decode32!(secret, padding: false)
    counter = div(System.os_time(:second), 30)
    digest = :crypto.mac(:hmac, :sha, key, <<counter::unsigned-big-64>>)
    offset = :binary.last(digest) &&& 0x0F
    <<_::binary-size(^offset), truncated::unsigned-big-32, _::binary>> = digest

    (truncated &&& 0x7FFFFFFF)
    |> rem(1_000_000)
    |> Integer.to_string()
    |> String.pad_leading(6, "0")
  end

  defp password_step(conn, user) do
    post(conn, ~p"/login", %{"username" => user.username, "password" => @password})
  end

  defp fully_logged_in?(conn), do: get_session(conn, :mfa_passed) == true

  describe "pending_verify (user already has a factor)" do
    test "GET /login/enroll is refused and leaves the real secret alone", %{conn: conn} do
      {user, _secret} = totp_user!()
      conn = password_step(conn, user)
      assert redirected_to(conn) == ~p"/login/totp"

      conn = conn |> recycle() |> get(~p"/login/enroll")

      assert redirected_to(conn) == ~p"/login/totp"
      after_get = reload(user)
      assert after_get.totp_secret_enc == user.totp_secret_enc
      assert after_get.totp_enabled == true
    end

    test "POST /login/enroll never mints a session, even with a valid code", %{conn: conn} do
      {user, secret} = totp_user!()
      conn = password_step(conn, user) |> recycle()

      conn = post(conn, ~p"/login/enroll", %{"code" => code(secret)})

      assert redirected_to(conn) == ~p"/login/totp"
      refute fully_logged_in?(conn)
      assert reload(user).totp_secret_enc == user.totp_secret_enc
    end

    test "the exploit chain (GET then POST with the new QR's code) fails", %{conn: conn} do
      {user, _secret} = totp_user!()
      conn = password_step(conn, user) |> recycle()
      conn = get(conn, ~p"/login/enroll")
      refute conn.status == 200, "enroll page rendered a fresh secret for a verify session"

      # Whatever secret the row holds now must not be usable through enroll.
      row = reload(user)
      minted = Orbit.Crypto.decrypt!(row.totp_secret_enc)
      conn = conn |> recycle() |> post(~p"/login/enroll", %{"code" => code(minted)})

      refute fully_logged_in?(conn)
      assert reload(user).totp_enabled == true
    end

    test "the legit verify path still logs in with the real factor", %{conn: conn} do
      {user, secret} = totp_user!()
      conn = password_step(conn, user) |> recycle()
      assert get(conn, ~p"/login/totp").status == 200

      conn = conn |> recycle() |> post(~p"/login/totp", %{"code" => code(secret)})

      assert redirected_to(conn) == ~p"/"
      assert fully_logged_in?(conn)
    end

    test "a pre-fix pending session without a recorded kind is refused", %{conn: conn} do
      {user, _secret} = totp_user!()

      conn =
        conn
        |> Plug.Test.init_test_session(%{
          mfa_user_id: user.id,
          mfa_pw_version: user.password_version
        })
        |> get(~p"/login/enroll")

      assert redirected_to(conn) == ~p"/login"
      assert reload(user).totp_secret_enc == user.totp_secret_enc
    end
  end

  describe "pending_enroll (user without any factor)" do
    test "GET renders the QR, POST with its code enrolls and logs in", %{conn: conn} do
      user = user!("admin", false)
      conn = password_step(conn, user)
      assert redirected_to(conn) == ~p"/login/enroll"

      conn = conn |> recycle() |> get(~p"/login/enroll")
      assert html_response(conn, 200) =~ "otpauth://"

      pending = reload(user)
      assert pending.totp_enabled == false
      secret = Orbit.Crypto.decrypt!(pending.totp_secret_enc)

      conn = conn |> recycle() |> post(~p"/login/enroll", %{"code" => code(secret)})

      assert redirected_to(conn) == ~p"/"
      assert fully_logged_in?(conn)
      assert reload(user).totp_enabled == true
    end

    test "the TOTP step is not reachable from an enroll session", %{conn: conn} do
      user = user!("admin", false)
      conn = password_step(conn, user) |> recycle()

      assert redirected_to(get(conn, ~p"/login/totp")) == ~p"/login/enroll"
    end

    test "re-checks the DB: a factor that appeared meanwhile blocks enrollment", %{conn: conn} do
      user = user!("admin", false)
      conn = password_step(conn, user) |> recycle()

      # Factor enrolled elsewhere after the password step (e.g. second tab).
      secret = Orbit.Auth.TOTP.generate_secret()

      enrolled =
        user
        |> Ecto.Changeset.change(
          totp_secret_enc: Orbit.Crypto.encrypt(secret),
          totp_enabled: true
        )
        |> Repo.update!()

      conn = get(conn, ~p"/login/enroll")
      assert redirected_to(conn) == ~p"/login"
      assert reload(user).totp_secret_enc == enrolled.totp_secret_enc

      conn = conn |> recycle() |> post(~p"/login/enroll", %{"code" => code(secret)})
      refute fully_logged_in?(conn)
    end
  end

  describe "stale pending session (right kind, user no longer valid)" do
    test "goes to the password form instead of looping on its own step", %{conn: conn} do
      {user, _secret} = totp_user!()
      conn = password_step(conn, user) |> recycle()
      user |> Ecto.Changeset.change(disabled: true) |> Repo.update!()

      assert redirected_to(get(conn, ~p"/login/totp")) == ~p"/login"
      assert redirected_to(conn |> recycle() |> get(~p"/login/enroll")) == ~p"/login/totp"
    end

    test "enroll kind: a password change voids the step", %{conn: conn} do
      user = user!("admin", false)
      conn = password_step(conn, user) |> recycle()

      user
      |> Ecto.Changeset.change(password_version: user.password_version + 1)
      |> Repo.update!()

      assert redirected_to(get(conn, ~p"/login/enroll")) == ~p"/login"
    end
  end

  describe "limiter gates the code steps (locked IP keeps no guesses)" do
    setup do
      on_exit(fn -> Orbit.Auth.LoginLimiter.record_success("127.0.0.1") end)
    end

    defp lock_ip!, do: for(_ <- 1..5, do: Orbit.Auth.LoginLimiter.record_failure("127.0.0.1"))

    test "TOTP: even the right code is refused while locked", %{conn: conn} do
      {user, secret} = totp_user!()
      conn = password_step(conn, user) |> recycle()
      lock_ip!()

      conn = post(conn, ~p"/login/totp", %{"code" => code(secret)})

      assert conn.status == 429
      refute fully_logged_in?(conn)
    end

    test "enroll: refused while locked, and no secret on the page", %{conn: conn} do
      user = user!("admin", false)
      conn = password_step(conn, user) |> recycle()
      conn = get(conn, ~p"/login/enroll")
      secret = Orbit.Crypto.decrypt!(reload(user).totp_secret_enc)
      lock_ip!()

      conn = conn |> recycle() |> post(~p"/login/enroll", %{"code" => code(secret)})

      assert conn.status == 429
      refute conn.resp_body =~ secret
      refute fully_logged_in?(conn)
      assert reload(user).totp_enabled == false
    end
  end

  describe "enrollment writes are conditional (stale struct races)" do
    test "begin refuses when the DB gained a factor after the struct was read" do
      stale = user!("admin", false)
      {_enrolled, _secret} = enable_totp!(stale)

      assert {:error, :factor_enrolled} = Orbit.Accounts.begin_totp_enrollment(stale)
      assert reload(stale).totp_enabled == true
    end

    test "confirm only enables the secret the code was checked against" do
      user = user!("admin", false)
      {:ok, {secret_a, _}} = Orbit.Accounts.begin_totp_enrollment(user)
      stale = reload(user)
      # Another session mints a new pending secret meanwhile.
      {:ok, {_secret_b, _}} = Orbit.Accounts.begin_totp_enrollment(reload(user))

      assert {:error, :factor_enrolled} =
               Orbit.Accounts.confirm_totp_enrollment(stale, code(secret_a))

      assert reload(user).totp_enabled == false
    end
  end

  defp enable_totp!(user) do
    secret = Orbit.Auth.TOTP.generate_secret()

    enrolled =
      user
      |> Ecto.Changeset.change(totp_secret_enc: Orbit.Crypto.encrypt(secret), totp_enabled: true)
      |> Repo.update!()

    {enrolled, secret}
  end
end
