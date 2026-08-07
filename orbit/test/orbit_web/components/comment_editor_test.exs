defmodule OrbitWeb.Components.CommentEditorTest do
  @moduledoc """
  The comment text renders INLINE (designer feedback 2026-08-07): a
  pencil-only badge hid the one thing the next operator was meant to
  read. Empty stays the quiet pencil affordance.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias OrbitWeb.Components.CommentEditor

  defp editor(attrs) do
    render_component(
      &CommentEditor.comment_editor/1,
      Keyword.merge([instance_id: 1, kind: "notes", entity_key: ""], attrs)
    )
  end

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
