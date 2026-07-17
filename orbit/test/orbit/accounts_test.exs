defmodule Orbit.AccountsTest do
  @moduledoc """
  DB-free login-flow tests (house style: struct fixtures, injected factor
  state) mirroring the password-step semantics of backend auth/routes.py.
  """

  use ExUnit.Case, async: true

  alias Orbit.Accounts
  alias Orbit.Accounts.User
  alias Orbit.Auth.Password

  @password "correct horse battery staple"

  defp user(attrs) do
    struct!(
      %User{
        id: 1,
        username: "alice",
        password_hash: Password.hash(@password),
        disabled: false,
        is_bootstrap: false,
        totp_enabled: false,
        totp_secret_enc: nil,
        groups: []
      },
      attrs
    )
  end

  defp no_factors(_user), do: %{totp: false, webauthn: false}

  describe "login_step/3 — password stage" do
    test "unknown username fails closed (dummy verify ran, no user leak)" do
      assert {:error, :invalid_credentials} = Accounts.login_step(nil, "whatever", &no_factors/1)
    end

    test "wrong password fails" do
      assert {:error, :invalid_credentials} =
               Accounts.login_step(user([]), "wrong", &no_factors/1)
    end

    test "disabled account fails AFTER the password check, distinct reason" do
      assert {:error, :account_disabled} =
               Accounts.login_step(user(disabled: true), @password, &no_factors/1)
    end

    test "bootstrap admin is password-only: session mintable immediately" do
      assert {:ok, {:done, %User{}}} =
               Accounts.login_step(user(is_bootstrap: true), @password, &no_factors/1)
    end

    test "enrolled factor → :verify challenge with factor flags" do
      factors = fn _ -> %{totp: true, webauthn: false} end

      assert {:ok, {:verify, %User{}, %{totp: true, webauthn: false}}} =
               Accounts.login_step(user([]), @password, factors)
    end

    test "no factor enrolled → mandatory :enroll stage, never a session" do
      assert {:ok, {:enroll, %User{}}} = Accounts.login_step(user([]), @password, &no_factors/1)
    end
  end

  describe "verify_totp/3 — second factor against the fernet-encrypted secret" do
    test "valid code passes with the enrolled secret" do
      # Fixed secret + python-verified vector from totp_test.exs.
      secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
      enc = Orbit.Crypto.encrypt(secret)
      u = user(totp_enabled: true, totp_secret_enc: enc)

      assert Accounts.verify_totp(u, "401544", at: 1_234_567_890, window: 0)
      refute Accounts.verify_totp(u, "000000", at: 1_234_567_890, window: 0)
    end

    test "user without an enrolled factor never passes (no bypass)" do
      refute Accounts.verify_totp(user([]), "123456", at: 0)
      refute Accounts.verify_totp(user(totp_enabled: true), "123456", at: 0)
      refute Accounts.verify_totp(user(totp_secret_enc: <<1, 2, 3>>), "123456", at: 0)
    end

    test "undecryptable secret (wrong key / corrupt blob) fails closed" do
      u = user(totp_enabled: true, totp_secret_enc: "gAAAAABnot-a-real-token")
      refute Accounts.verify_totp(u, "123456", at: 0)
    end
  end
end
