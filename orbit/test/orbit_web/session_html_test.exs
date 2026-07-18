defmodule OrbitWeb.SessionHTMLTest do
  @moduledoc """
  The /login/totp page adapts to the pending user's actual factors: the code
  form only for TOTP, the passkey button only for WebAuthn. A passkey-only user
  must NOT see a code field they can't fill (the bug the old "always render
  TOTP" placeholder had).
  """

  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

  defp render_totp(factors) do
    factors
    |> Map.put(:error, nil)
    |> OrbitWeb.SessionHTML.totp()
    |> rendered_to_string()
  end

  test "passkey-only user: passkey button shown, code form hidden" do
    html = render_totp(%{totp: false, webauthn: true})

    assert html =~ ~s(id="passkey-login")
    assert html =~ "Sign in with your passkey"
    refute html =~ ~s(name="code")
  end

  test "totp-only user: code form shown, no passkey button" do
    html = render_totp(%{totp: true, webauthn: false})

    assert html =~ ~s(name="code")
    assert html =~ "6-digit code"
    refute html =~ ~s(id="passkey-login")
  end

  test "both factors: code form and passkey button present" do
    html = render_totp(%{totp: true, webauthn: true})

    assert html =~ ~s(name="code")
    assert html =~ ~s(id="passkey-login")
  end
end
