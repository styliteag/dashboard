defmodule OrbitWeb.Design do
  @moduledoc """
  The switchable UI designs, each in a light and a dark mode
  (link-shortener Design.ex port — same UX contract). Design and mode
  combine into a daisyUI theme name (`"orbit-dark"`, `"bench-light"`, …)
  rendered as `data-theme` on `<html>`.

  Both choices live in long-lived cookies (`orbit_design`, `orbit_mode`).
  Without an explicit mode each design uses its native one: Orbit is
  dark-first (the classic slate+emerald dashboard), Bench and Soft are
  light-first.

  The registry is data-driven and can be replaced at compile time via

      config :orbit, :designs, [
        %{id: "orbit", name: "Orbit", default_mode: "dark"},
        ...
      ]

  so a downstream build can add designs without touching this module.
  Every entry needs a matching `<id>-light`/`<id>-dark` daisyUI theme
  block in `assets/css/app.css` — themes are compiled, not runtime data.
  The first entry is the default design.
  """

  @default_designs [
    %{id: "orbit", name: "Orbit", default_mode: "dark"},
    %{id: "bench", name: "Bench", default_mode: "light"},
    %{id: "soft", name: "Soft", default_mode: "light"}
  ]

  @designs Application.compile_env(:orbit, :designs, @default_designs)
  @ids Enum.map(@designs, & &1.id)
  @modes ~w(light dark)
  @default hd(@ids)

  def all, do: @ids
  def modes, do: @modes
  def default, do: @default

  def validate(design) when design in @ids, do: design
  def validate(_other), do: @default

  @doc "Validated explicit mode, or nil meaning: use the design's default."
  def validate_mode(mode) when mode in @modes, do: mode
  def validate_mode(_other), do: nil

  def default_mode(design), do: find(design).default_mode

  @doc "daisyUI theme name for a design plus optional explicit mode."
  def theme(design, mode \\ nil), do: "#{design}-#{mode || default_mode(design)}"

  def name(design), do: find(design).name

  def mode_name("light"), do: "Light"
  def mode_name("dark"), do: "Dark"

  defp find(id), do: Enum.find(@designs, hd(@designs), &(&1.id == id))
end
