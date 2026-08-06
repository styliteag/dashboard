defmodule OrbitWeb.Components.StatusTest do
  @moduledoc """
  The shared status indicator must carry three redundant channels — colour,
  a state-specific glyph shape, and the state word (UI/UX review 2026-08-06,
  A-B3/S1). If any of these assertions fails, a status somewhere in the app
  is back to colour-only.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest
  import OrbitWeb.CoreComponents, only: [status: 1]

  defp dot(state, label \\ nil),
    do: render_component(&status/1, state: state, label: label)

  test "dot variant hides the word visually but keeps it for AT and hover" do
    html = dot(:up, "online")

    assert html =~ ~s|sr-only|
    assert html =~ "online"
    assert html =~ ~s|title="online"|
  end

  test "each state renders a distinct glyph shape, not just a colour" do
    assert dot(:up) =~ "<circle"
    assert dot(:warn) =~ "M5 0.8"
    assert dot(:down) =~ "M1.6 1.6"
    assert dot(:unknown) =~ "<rect"
  end

  test "states map to their semantic colour roles" do
    assert dot(:up) =~ "text-primary"
    assert dot(:warn) =~ "text-warning"
    assert dot(:down) =~ "text-error"
    assert dot(:unknown) =~ "text-base-content/60"
  end

  test "badge variant shows the word visibly on the tinted pill" do
    html = render_component(&status/1, state: :warn, label: "degraded", variant: :badge)

    assert html =~ "degraded"
    assert html =~ "bg-warning/15"
    refute html =~ "sr-only"
  end

  test "label defaults to the state name" do
    assert dot(:down) =~ ~s|title="down"|
  end

  # UI/UX review 2026-08-06, D-8: panels take the THEME's box radius — a
  # fixed rounded-lg silently overrode every design's shape tokens.
  test "panel uses the theme radius token and maps densities to padding" do
    panel = fn opts ->
      render_component(
        &OrbitWeb.CoreComponents.panel/1,
        Keyword.merge(
          [inner_block: [%{inner_block: fn _, _ -> "BODY" end}]],
          opts
        )
      )
    end

    assert panel.([]) =~ "rounded-[var(--radius-box)]"
    assert panel.([]) =~ "p-4"
    assert panel.(density: :compact) =~ "p-3"
    assert panel.(density: :roomy) =~ "p-6"
  end
end
