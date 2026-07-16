defmodule Orbit.Auth.ScopeTest do
  @moduledoc """
  Mirror of backend tests/test_group_scoping.py — the change-frozen semantics.
  House style like the backend: no DB rows; SQL asserted as compiled text,
  membership asserted on structs. Live end-to-end proof comes with the
  contract suite (M2).
  """

  use ExUnit.Case, async: true

  import Ecto.Query

  alias Orbit.Accounts.{ApiKey, Group, User}
  alias Orbit.Auth.Scope
  alias Orbit.Instances.Instance

  defp user(group_ids), do: %User{id: 1, groups: Enum.map(group_ids, &%Group{id: &1})}
  defp key(group_ids), do: %ApiKey{id: 1, groups: Enum.map(group_ids, &%Group{id: &1})}
  defp inst(group_id), do: %Instance{id: 42, group_id: group_id, deleted_at: nil}

  defp sql(query), do: Orbit.Repo.to_sql(:all, query) |> elem(0)

  describe "scope/2 — WHERE clause semantics" do
    test "nil principal (internal caller) is unscoped" do
      assert sql(Scope.scope(Instance, nil)) == sql(from(i in Instance))
    end

    test "user with groups filters on group_id" do
      q = Scope.scope(Instance, user([1, 3]))
      assert sql(q) =~ "`group_id` IN "
    end

    test "user with ZERO groups sees NOTHING (WHERE false, not unscoped)" do
      q = Scope.scope(Instance, user([]))
      assert sql(q) =~ "FALSE"
      refute sql(q) == sql(from(i in Instance))
    end

    test "api key with ZERO bindings is GLOBAL (inverted empty-set semantics)" do
      assert sql(Scope.scope(Instance, key([]))) == sql(from(i in Instance))
    end

    test "api key with bindings filters on group_id" do
      assert sql(Scope.scope(Instance, key([2]))) =~ "`group_id` IN "
    end

    test "composes onto an existing query instead of replacing it" do
      base = from(i in Instance, where: is_nil(i.deleted_at))
      q = Scope.scope(base, user([1]))
      assert sql(q) =~ "`deleted_at` IS NULL"
      assert sql(q) =~ "`group_id` IN "
    end
  end

  describe "can_access?/2 — membership assertion" do
    test "nil principal always passes (internal caller)" do
      assert Scope.can_access?(nil, inst(999))
    end

    test "user sees only their groups' instances" do
      assert Scope.can_access?(user([1, 3]), inst(3))
      refute Scope.can_access?(user([1, 3]), inst(2))
    end

    test "user with zero groups sees nothing" do
      refute Scope.can_access?(user([]), inst(1))
    end

    test "NO superadmin bypass: a pure superadmin without groups sees nothing" do
      superadmin = %User{id: 9, is_superadmin: true, role: "view_only", groups: []}
      refute Scope.can_access?(superadmin, inst(1))
    end

    test "api key with zero bindings is global" do
      assert Scope.can_access?(key([]), inst(1))
      assert Scope.can_access?(key([]), inst(999))
    end

    test "bound api key sees only its groups" do
      assert Scope.can_access?(key([2]), inst(2))
      refute Scope.can_access?(key([2]), inst(1))
    end
  end
end
