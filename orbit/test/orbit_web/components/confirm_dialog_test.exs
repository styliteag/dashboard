defmodule OrbitWeb.Components.ConfirmDialogTest do
  @moduledoc """
  The tiered confirmation dialog (UI/UX review 2026-08-06, U-M5): it must
  name the affected boxes, escalate visually with blast radius, and keep
  the type-to-confirm submit disabled until the operator typed the phrase.
  The server-side re-check lives in each page's on_confirm handler — this
  component is the prompt, not the gate.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest
  import OrbitWeb.CoreComponents, only: [confirm_dialog: 1]

  defp dialog(overrides) do
    render_component(
      &confirm_dialog/1,
      Keyword.merge(
        [
          title: "Reboot 3 instance(s)",
          tier: :type_to_confirm,
          on_confirm: "bulk_run",
          on_cancel: "bulk_cancel",
          typed: "",
          must_type: "3",
          items: ["opn1", "pf1", "pf2"],
          inner_block: [%{inner_block: fn _, _ -> "All boxes go down." end}]
        ],
        overrides
      )
    )
  end

  test "names every affected box" do
    html = dialog([])

    for name <- ["opn1", "pf1", "pf2"], do: assert(html =~ name)
  end

  test "type_to_confirm keeps submit disabled until the phrase matches" do
    # The class list always contains disabled: variants — match the actual
    # HTML attribute on the submit button instead.
    assert dialog(typed: "") =~ ~s|type="submit" disabled|
    assert dialog(typed: "2") =~ ~s|type="submit" disabled|
    refute dialog(typed: "3") =~ ~s|type="submit" disabled|
  end

  test "escape is wired to cancel and the dialog is announced as modal" do
    html = dialog([])

    assert html =~ ~s|phx-key="escape"|
    assert html =~ ~s|phx-window-keydown="bulk_cancel"|
    assert html =~ ~s|aria-modal="true"|
  end

  test "tiers change the framing, info has no typed input" do
    info = dialog(tier: :info, must_type: nil)

    assert info =~ "border-base-300"
    refute info =~ ~s|name="typed"|

    assert dialog(tier: :danger, must_type: nil) =~ "border-error/50"
    assert dialog([]) =~ "border-warning/50"
  end
end
