defmodule Orbit.ApiKeysScopeTest do
  @moduledoc """
  API-key management is scoped like reveal: a group-scoped admin lists,
  revokes and purges only keys bound WITHIN his groups. Global keys (no
  binding) and other tenants' keys are superadmin-only — out-of-scope ids
  answer the same `:not_found` as missing ones (no oracle).
  """
  use Orbit.DataCase, async: false

  alias Orbit.Accounts.{Group, User}
  alias Orbit.ApiKeys

  defp group, do: Repo.insert!(%Group{name: "ak-#{System.unique_integer([:positive])}"})

  setup do
    mine = group()
    other = group()
    root = %User{id: 1, is_superadmin: true, groups: []}
    admin = %User{id: 2, is_superadmin: false, role: "admin", groups: [mine]}

    {:ok, own} = ApiKeys.create(%{"name" => "own", "group_ids" => [mine.id]}, admin)
    {:ok, global} = ApiKeys.create(%{"name" => "global"}, root)
    {:ok, foreign} = ApiKeys.create(%{"name" => "foreign", "group_ids" => [other.id]}, root)

    {:ok, root: root, admin: admin, own: own.id, global: global.id, foreign: foreign.id}
  end

  test "list: admin sees only his bound keys, superadmin all", c do
    ids = c.admin |> ApiKeys.list() |> Enum.map(& &1.id)
    assert c.own in ids
    refute c.global in ids
    refute c.foreign in ids

    all = c.root |> ApiKeys.list() |> Enum.map(& &1.id)
    assert Enum.all?([c.own, c.global, c.foreign], &(&1 in all))
  end

  test "revoke/purge out of scope is :not_found and changes nothing", c do
    for id <- [c.global, c.foreign] do
      assert {:error, :not_found} = ApiKeys.revoke(id, c.admin)
      assert {:error, :not_found} = ApiKeys.purge(id, c.admin)
    end

    assert Enum.all?(ApiKeys.list(c.root), &is_nil(&1.revoked_at))
  end

  test "in scope: revoke then purge works", c do
    assert :ok = ApiKeys.revoke(c.own, c.admin)
    assert :ok = ApiKeys.purge(c.own, c.admin)
    refute c.own in Enum.map(ApiKeys.list(c.root), & &1.id)
  end

  test "superadmin may revoke a global key", c do
    assert :ok = ApiKeys.revoke(c.global, c.root)
  end
end
