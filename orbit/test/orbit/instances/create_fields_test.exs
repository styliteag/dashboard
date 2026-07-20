defmodule Orbit.Instances.CreateFieldsTest do
  @moduledoc """
  Create carries the same descriptive fields the edit form offers.

  Regression: the create form (and `insert_instance` behind it) only wrote
  name/group/urls/credentials. Tags, ping URL, push interval and notes were
  edit-only, so a freshly created box was untagged — and the fleet page's tag
  chips, which filter on exact matches, could only ever be populated by a
  second trip through the edit form. Fails on the pre-fix tree, where the
  four fields come back nil/[].
  """
  use Orbit.DataCase, async: false

  alias Orbit.Instances

  setup do
    group =
      Repo.insert!(%Orbit.Accounts.Group{
        name: "create-fields-#{System.unique_integer([:positive])}"
      })

    {:ok, group_id: group.id}
  end

  test "tags, ping url, push interval and notes are stored at creation", %{group_id: gid} do
    {:ok, inst} =
      Instances.create_instance(
        %{
          "name" => "create-fields-box",
          "device_type" => "opnsense",
          "transport" => "push",
          "tags" => " LAB , customer-x ,, LAB ",
          "ping_url" => "https://10.0.0.1:4444",
          "push_interval_seconds" => "60",
          "notes" => "rack 3"
        },
        gid
      )

    # Same coercion as the edit path: trimmed, blanks dropped, de-duplicated —
    # " LAB" and "LAB" must not become two chips.
    assert inst.tags == ["LAB", "customer-x"]
    assert inst.ping_url == "https://10.0.0.1:4444"
    assert inst.push_interval_seconds == 60
    assert inst.notes == "rack 3"
  end

  test "omitted fields stay empty rather than blank strings", %{group_id: gid} do
    {:ok, inst} =
      Instances.create_instance(
        %{"name" => "create-fields-bare", "device_type" => "opnsense", "ping_url" => "  "},
        gid
      )

    assert inst.tags == []
    assert inst.ping_url == nil
    assert inst.notes == nil
    # Blank interval = no per-instance override; the global default applies.
    assert inst.push_interval_seconds == nil
  end
end
