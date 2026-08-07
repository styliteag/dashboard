defmodule OrbitWeb.Components.CommentEditorTest do
  @moduledoc """
  `text/4` must accept both comment shapes the app carries, and the
  comment TEXT renders inline (designer feedback 2026-08-07 — a
  pencil-only badge hid the one thing the next operator was meant to
  read).

  Regression (text/4): it took the `lookup/1` map only. When the instance
  detail page started using the editor it passed its own plain list
  (`Comments.list_for_instance/1`) and `Map.get/3` raised BadMapError —
  during render, so the whole page answered 500 rather than just dropping
  a badge.

  Sits in components/ since 2026-08-07; a second file at the old
  test/orbit_web/ path once redefined this module and broke compilation
  as a parallel-compile race — one module, one file.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

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

  # -- inline text rendering (designer feedback 2026-08-07) -----------------

  defp editor(attrs) do
    render_component(
      &CommentEditor.comment_editor/1,
      Keyword.merge([instance_id: 1, kind: "notes", entity_key: ""], attrs)
    )
  end

  describe "inline rendering" do
    test "a writable row shows the comment text inline, truncated" do
      html = editor(writable: true, text: "replaced PSU 2026-08-01, watch temps")
      assert html =~ "replaced PSU 2026-08-01, watch temps"
      assert html =~ "truncate"
    end

    test "a read-only viewer sees the text too, not just a pencil" do
      html = editor(writable: false, text: "replaced PSU")
      assert html =~ "replaced PSU"
      assert html =~ "cursor-help"
    end

    test "empty comment keeps the quiet pencil affordance without stray text" do
      html = editor(writable: true, text: nil)
      assert html =~ "Add comment"
      refute html =~ "italic"

      # read-only + empty renders nothing at all
      refute editor(writable: false, text: "") =~ "<svg"
    end
  end
end
