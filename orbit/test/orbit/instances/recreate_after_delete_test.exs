defmodule Orbit.Instances.RecreateAfterDeleteTest do
  @moduledoc """
  Soft delete must free the slug for reuse — the documented generated-column
  contract (`soft_delete/1`: "the slug is freed for reuse").

  Regression: `uq_instances_slug` was a UNIQUE on the RAW slug column, while
  only the name got the `*_active_key` generated-column treatment. A deleted
  instance kept its slug forever: recreating a box under its old name passed
  the app-side checks (they exclude deleted rows), then hit the DB constraint
  and surfaced as "instance name or slug already exists" — with no visible
  row explaining why. Fails on the pre-fix schema.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Instances

  setup do
    group =
      Repo.insert!(%Orbit.Accounts.Group{
        name: "recreate-#{System.unique_integer([:positive])}"
      })

    {:ok, group_id: group.id}
  end

  defp create!(name, gid, extra \\ %{}) do
    {:ok, inst} =
      Instances.create_instance(
        Map.merge(
          %{"name" => name, "device_type" => "proxmox", "transport" => "push"},
          extra
        ),
        gid
      )

    inst
  end

  test "same name (auto slug) can be created again after a soft delete", %{group_id: gid} do
    inst = create!("recreate-box", gid)
    assert inst.slug == "recreate-box"

    {:ok, _} = Instances.soft_delete(inst)

    recreated = create!("recreate-box", gid)
    # The freed slug is reused, not suffixed to -2 (nothing active holds it).
    assert recreated.slug == "recreate-box"
    assert recreated.id != inst.id
  end

  test "an explicit slug is freed by a soft delete too", %{group_id: gid} do
    inst = create!("recreate-explicit", gid, %{"slug" => "my-slug"})
    {:ok, _} = Instances.soft_delete(inst)

    recreated = create!("recreate-explicit-2", gid, %{"slug" => "my-slug"})
    assert recreated.slug == "my-slug"
  end

  test "an ACTIVE instance still blocks its slug", %{group_id: gid} do
    create!("recreate-active", gid, %{"slug" => "taken-slug"})

    assert {:error, :slug_taken} =
             Instances.create_instance(
               %{
                 "name" => "recreate-active-2",
                 "device_type" => "proxmox",
                 "slug" => "taken-slug"
               },
               gid
             )
  end
end
