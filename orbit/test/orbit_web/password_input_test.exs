defmodule OrbitWeb.PasswordInputTest do
  @moduledoc """
  One password rule for self-service change, admin reset and user creation:
  a string of 8..256 characters (Argon2 hashing an arbitrarily large blob is
  a CPU sink). Usernames: 1..64 characters, no whitespace or control
  characters. Wrongly typed form values are a 400, never a crash.
  """
  use OrbitWeb.ConnCase, async: false

  alias Orbit.Accounts.Admin
  alias Orbit.Auth.Password

  defp user!(role \\ "admin") do
    {:ok, u} =
      Admin.create_user(%{
        "username" => "pwi-#{System.unique_integer([:positive])}",
        "password" => "long-enough-pw",
        "role" => role
      })

    u
  end

  test "Password.validate_new/1" do
    assert :ok = Password.validate_new("12345678")
    assert :ok = Password.validate_new(String.duplicate("a", 256))
    assert {:error, :password_too_short} = Password.validate_new("1234567")
    assert {:error, :password_too_long} = Password.validate_new(String.duplicate("a", 257))
    assert {:error, :password_invalid} = Password.validate_new(%{"x" => 1})
    assert {:error, :password_invalid} = Password.validate_new(nil)
  end

  test "admin reset applies the same rule" do
    target = user!("user")
    actor = user!()

    assert {:error, :password_too_short} =
             Admin.update_user(target, %{"new_password" => "x"}, actor)

    assert {:error, :password_too_long} =
             Admin.update_user(target, %{"new_password" => String.duplicate("a", 300)}, actor)
  end

  test "create: long password and bad usernames are refused" do
    assert {:error, :password_too_long} =
             Admin.create_user(%{
               "username" => "pwi-long",
               "password" => String.duplicate("a", 300)
             })

    for bad <- ["a b", "tab\tname", "nl\nname", String.duplicate("u", 65), %{"x" => 1}] do
      assert {:error, :username_invalid} =
               Admin.create_user(%{"username" => bad, "password" => "long-enough-pw"}),
             inspect(bad)
    end
  end

  test "self-service change with non-string values is a 400, not a crash", %{conn: conn} do
    u = user!()

    conn =
      conn
      |> Plug.Test.init_test_session(%{
        user_id: u.id,
        password_version: u.password_version,
        mfa_passed: true
      })
      |> post("/password", %{"old_password" => %{"a" => 1}, "new_password" => ["x"]})

    assert conn.status == 400
  end

  test "self-service change refuses an overlong new password", %{conn: conn} do
    u = user!()
    long = String.duplicate("a", 300)

    conn =
      conn
      |> Plug.Test.init_test_session(%{
        user_id: u.id,
        password_version: u.password_version,
        mfa_passed: true
      })
      |> post("/password", %{
        "old_password" => "long-enough-pw",
        "new_password" => long,
        "confirm_password" => long
      })

    assert html_response(conn, 400) =~ "at most 256"
  end
end
