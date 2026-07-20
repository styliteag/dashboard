defmodule Orbit.Instances.KnownTagsTest do
  @moduledoc """
  Suggestion list for the tag picker is group-scoped (invariant 1).

  Tags carry customer names ("CARLEB", "CVO", … on the real fleet), so an
  unscoped `known_tags/1` would spell out another MSP customer's name in the
  dropdown of a user who cannot see a single one of their boxes — a scope
  leak through an autocomplete. These fail on any implementation that skips
  Scope.scope/2.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Accounts.Group
  alias Orbit.Accounts.User
  alias Orbit.Instances

  setup do
    mine = Repo.insert!(%Group{name: "known-tags-mine-#{unique()}"})
    theirs = Repo.insert!(%Group{name: "known-tags-theirs-#{unique()}"})

    {:ok, _} = create("mine-#{unique()}", mine.id, "LAB, shared")
    {:ok, _} = create("theirs-#{unique()}", theirs.id, "customer-x, shared")

    {:ok, mine: mine, theirs: theirs}
  end

  defp unique, do: System.unique_integer([:positive])

  defp create(name, group_id, tags) do
    Instances.create_instance(
      %{"name" => name, "device_type" => "opnsense", "tags" => tags},
      group_id
    )
  end

  test "a user only sees the tags of their own groups", %{mine: mine} do
    tags = Instances.known_tags(%User{groups: [mine]})

    assert tags == ["LAB", "shared"]
    refute "customer-x" in tags
  end

  test "a user in both groups sees the union, de-duplicated", %{mine: mine, theirs: theirs} do
    assert Instances.known_tags(%User{groups: [mine, theirs]}) ==
             ["LAB", "customer-x", "shared"]
  end

  test "a user with no groups sees nothing (the inverted empty-set semantics)" do
    assert Instances.known_tags(%User{groups: []}) == []
  end

  test "soft-deleted instances drop out of the vocabulary", %{mine: mine} do
    {:ok, gone} = create("gone-#{unique()}", mine.id, "retired-tag")
    {:ok, _} = Instances.soft_delete(gone)

    refute "retired-tag" in Instances.known_tags(%User{groups: [mine]})
  end
end
