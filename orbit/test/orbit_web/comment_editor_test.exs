defmodule OrbitWeb.Components.CommentEditorTest do
  @moduledoc """
  `text/4` must accept both comment shapes the app carries.

  Regression: it took the `lookup/1` map only. When the instance detail page
  started using the editor it passed its own plain list
  (`Comments.list_for_instance/1`) and `Map.get/3` raised BadMapError — during
  render, so the whole page answered 500 rather than just dropping a badge.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.Components.CommentEditor

  defp comment(attrs \\ []) do
    struct!(
      %Orbit.Comments.EntityComment{
        instance_id: 5,
        kind: "ipsec",
        entity_key: "bonis-test",
        comment: "watch this tunnel",
        updated_by: "admin"
      },
      attrs
    )
  end

  describe "the lookup map shape (fleet pages)" do
    test "finds a comment" do
      map = %{{5, "ipsec", "bonis-test"} => comment()}

      assert CommentEditor.text(map, 5, "ipsec", "bonis-test") == "watch this tunnel"
    end

    test "misses cleanly" do
      assert CommentEditor.text(%{}, 5, "ipsec", "bonis-test") == nil
    end
  end

  describe "the plain list shape (per-instance page)" do
    test "finds a comment" do
      assert CommentEditor.text([comment()], 5, "ipsec", "bonis-test") == "watch this tunnel"
    end

    test "requires all three of instance, kind and key to match" do
      list = [comment()]

      assert CommentEditor.text(list, 6, "ipsec", "bonis-test") == nil
      assert CommentEditor.text(list, 5, "cert", "bonis-test") == nil
      assert CommentEditor.text(list, 5, "ipsec", "other-tunnel") == nil
    end

    test "compares the entity key as a string — monitor ids arrive as integers" do
      list = [comment(kind: "connectivity", entity_key: "9")]

      assert CommentEditor.text(list, 5, "connectivity", 9) == "watch this tunnel"
      assert CommentEditor.text(list, 5, "connectivity", "9") == "watch this tunnel"
    end

    test "an empty list is not a match" do
      assert CommentEditor.text([], 5, "ipsec", "bonis-test") == nil
    end
  end

  test "anything else degrades to nil instead of taking the page down" do
    assert CommentEditor.text(nil, 5, "ipsec", "x") == nil
  end
end
