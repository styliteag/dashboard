defmodule OrbitWeb.Components.FieldTest do
  @moduledoc """
  Form-field wrapper (UI/UX review 2026-08-06, A-M1/A-M3/U-M4): labels at
  /70 (the old /60 fails AA in the light designs), a VISIBLE required
  marker (only "(optional)" suffixes existed, implying an inverse
  convention), and a constraint note for immutable fields.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest
  import OrbitWeb.CoreComponents, only: [field: 1]

  defp render_field(overrides) do
    render_component(
      &field/1,
      Keyword.merge(
        [
          label: "Name",
          inner_block: [%{inner_block: fn _, _ -> "INPUT" end}]
        ],
        overrides
      )
    )
  end

  test "label renders at the AA-safe /70 tint" do
    assert render_field([]) =~ "text-base-content/70"
    refute render_field([]) =~ "text-base-content/60"
  end

  test "required renders a visible marker, absent by default" do
    assert render_field(required: true) =~ "*"
    refute render_field([]) =~ ~s|title="required"|
  end

  test "note carries constraints like immutability" do
    html = render_field(note: "Cannot be changed after creation.")

    assert html =~ "Cannot be changed after creation."
  end

  test "field error is announced" do
    html = render_field(error: "slug is already in use")

    assert html =~ ~s|role="alert"|
    assert html =~ "slug is already in use"
  end
end
