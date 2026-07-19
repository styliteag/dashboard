defmodule Orbit.Auth.BootstrapTest do
  @moduledoc """
  Port parity for auth/bootstrap.py's creation half.

  Regression: the orbit cutover ported only the RETIREMENT half of the bootstrap
  lifecycle (`retire_bootstrap/1`, the *_DISABLED flags). Nothing read
  DASH_ADMIN_PASSWORD / DASH_SUPERADMIN_PASSWORD and nothing ever created a seed
  account, so a greenfield database had no account at all and nobody could log
  in. These tests fail on the pre-fix tree, where the module does not exist.
  """
  use Orbit.DataCase, async: false

  import Ecto.Query

  alias Orbit.Accounts.User
  alias Orbit.Auth.Bootstrap
  alias Orbit.Auth.Password
  alias Orbit.Repo

  setup do
    prev = {
      Application.get_env(:orbit, :admin_password),
      Application.get_env(:orbit, :superadmin_password),
      Application.get_env(:orbit, :admin_disabled_raw),
      Application.get_env(:orbit, :superadmin_disabled_raw)
    }

    Application.put_env(:orbit, :admin_password, "seed-admin-pw")
    Application.put_env(:orbit, :superadmin_password, "seed-super-pw")
    Application.put_env(:orbit, :admin_disabled_raw, "auto")
    Application.put_env(:orbit, :superadmin_disabled_raw, "auto")

    on_exit(fn ->
      {a, s, ad, sd} = prev
      Application.put_env(:orbit, :admin_password, a)
      Application.put_env(:orbit, :superadmin_password, s)
      Application.put_env(:orbit, :admin_disabled_raw, ad)
      Application.put_env(:orbit, :superadmin_disabled_raw, sd)
    end)

    :ok
  end

  defp seed(superadmin?) do
    Repo.one(from(u in User, where: u.is_bootstrap == true and u.is_superadmin == ^superadmin?))
  end

  defp real_admin(attrs \\ %{}) do
    %User{}
    |> Ecto.Changeset.change(
      Map.merge(
        %{
          username: "real-#{System.unique_integer([:positive])}",
          password_hash: Password.hash("irrelevant"),
          password_version: 1,
          role: "admin",
          is_superadmin: false,
          is_bootstrap: false,
          totp_enabled: false,
          disabled: false,
          created_at: DateTime.utc_now() |> DateTime.truncate(:second)
        },
        attrs
      )
    )
    |> Repo.insert!()
  end

  describe "resolve_mode/1" do
    test "maps the python truthy/falsey spellings" do
      for v <- ~w(1 true yes on TRUE On), do: assert(Bootstrap.resolve_mode(v) == "disabled")
      for v <- ~w(0 false no off FALSE Off), do: assert(Bootstrap.resolve_mode(v) == "enabled")
      for v <- ["auto", "", "nonsense", nil], do: assert(Bootstrap.resolve_mode(v) == "auto")
    end
  end

  describe "default group" do
    test "seeds group 1 \"default\" on an empty groups table (alembic 028 parity)" do
      assert Repo.aggregate(Orbit.Accounts.Group, :count) == 0

      Bootstrap.run()

      g = Repo.one(from(g in Orbit.Accounts.Group, where: g.name == "default"))
      assert g.id == 1
    end

    test "leaves an existing groups table alone" do
      Repo.insert!(%Orbit.Accounts.Group{
        id: 7,
        name: "existing",
        created_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

      Bootstrap.run()

      assert Repo.aggregate(Orbit.Accounts.Group, :count) == 1
      assert Repo.one(from(g in Orbit.Accounts.Group, select: g.name)) == "existing"
    end

    test "the seed admin joins default, the seed superadmin does NOT" do
      Bootstrap.run()

      admin = seed(false)
      super_ = seed(true)

      assert Repo.all(from(ug in "user_groups", select: ug.user_id)) == [admin.id],
             "only the admin may hold a membership — superadmin manages rights, not instances"

      refute Enum.member?(
               Repo.all(from(ug in "user_groups", select: ug.user_id)),
               super_.id
             )
    end
  end

  describe "first start" do
    test "creates both password-only seeds" do
      assert Repo.aggregate(User, :count) == 0

      Bootstrap.run()

      admin = seed(false)
      assert admin.username == "admin"
      assert admin.role == "admin"
      assert admin.is_bootstrap
      refute admin.disabled
      assert Password.verify("seed-admin-pw", admin.password_hash)

      # Rights management only — view_only role, power carried by the flag.
      super_ = seed(true)
      assert super_.username == "superadmin"
      assert super_.role == "view_only"
      assert super_.is_superadmin
      assert Password.verify("seed-super-pw", super_.password_hash)
    end

    test "creates nothing when the password is unset" do
      Application.put_env(:orbit, :admin_password, nil)
      Application.put_env(:orbit, :superadmin_password, nil)

      Bootstrap.run()

      assert Repo.aggregate(User, :count) == 0
    end

    test "*_DISABLED=1 creates the seed already disabled" do
      Application.put_env(:orbit, :admin_disabled_raw, "1")

      Bootstrap.run()

      assert seed(false).disabled
    end
  end

  describe "auto mode on an existing database" do
    test "retires the seed once a real admin exists" do
      Bootstrap.run()
      refute seed(false).disabled

      real_admin()
      Bootstrap.run()

      assert seed(false).disabled, "seed must auto-disable once a real admin exists"
    end

    test "does not create a seed when a real admin is already present" do
      real_admin()

      Bootstrap.run()

      assert seed(false) == nil
    end

    test "break-glass: re-enables and resets the password when no real admin remains" do
      Bootstrap.run()
      real = real_admin()
      Bootstrap.run()
      assert seed(false).disabled

      before = seed(false)
      Repo.update_all(from(u in User, where: u.id == ^real.id), set: [disabled: true])
      Application.put_env(:orbit, :admin_password, "rotated-pw")

      Bootstrap.run()

      after_ = seed(false)
      refute after_.disabled
      assert Password.verify("rotated-pw", after_.password_hash)

      assert after_.password_version == before.password_version + 1,
             "password_version must bump so lingering sessions die"
    end
  end

  describe "forced modes" do
    test "*_DISABLED=1 keeps a lone seed disabled instead of breaking glass" do
      Bootstrap.run()
      Application.put_env(:orbit, :admin_disabled_raw, "1")

      Bootstrap.run()

      assert seed(false).disabled
    end

    test "*_DISABLED=0 keeps the seed enabled even next to a real admin" do
      Bootstrap.run()
      real_admin()
      Application.put_env(:orbit, :admin_disabled_raw, "0")

      Bootstrap.run()

      refute seed(false).disabled, "an explicitly forced-on seed must not auto-retire"
    end
  end

  test "is idempotent — a second run changes nothing" do
    Bootstrap.run()
    before = {seed(false), seed(true)}

    Bootstrap.run()

    assert {seed(false), seed(true)} == before
    assert Repo.aggregate(User, :count) == 2
  end
end
