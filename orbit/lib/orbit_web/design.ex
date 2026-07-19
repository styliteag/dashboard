defmodule OrbitWeb.Design do
  @moduledoc """
  The three switchable UI designs, each in a light and a dark mode
  (link-shortener Design.ex port — same UX contract). Design and mode
  combine into a daisyUI theme name (`"orbit-dark"`, `"bench-light"`, …)
  rendered as `data-theme` on `<html>`.

  Both choices live in long-lived cookies (`orbit_design`, `orbit_mode`).
  Without an explicit mode each design uses its native one: Orbit is
  dark-first (the classic slate+emerald dashboard), Bench and Soft are
  light-first.
  """

  @designs ~w(orbit bench soft)
  @modes ~w(light dark)
  @default "orbit"

  def all, do: @designs
  def modes, do: @modes
  def default, do: @default

  def validate(design) when design in @designs, do: design
  def validate(_other), do: @default

  @doc "Validated explicit mode, or nil meaning: use the design's default."
  def validate_mode(mode) when mode in @modes, do: mode
  def validate_mode(_other), do: nil

  def default_mode("orbit"), do: "dark"
  def default_mode(_light_first), do: "light"

  @doc "daisyUI theme name for a design plus optional explicit mode."
  def theme(design, mode \\ nil), do: "#{design}-#{mode || default_mode(design)}"

  def name("orbit"), do: "Orbit"
  def name("bench"), do: "Bench"
  def name("soft"), do: "Soft"

  def mode_name("light"), do: "Light"
  def mode_name("dark"), do: "Dark"
end
