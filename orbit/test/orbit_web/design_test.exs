defmodule OrbitWeb.DesignTest do
  use ExUnit.Case, async: true

  alias OrbitWeb.Design

  # Prefix assertion, not equality: downstream builds may append designs via
  # `config :orbit, :designs` and still run this suite unchanged.
  test "all/0 starts with the built-in designs in order" do
    assert Enum.take(Design.all(), 3) == ["orbit", "bench", "soft"]
  end

  test "default/0 is the first design" do
    assert Design.default() == "orbit"
  end

  test "validate/1 keeps known designs and falls back to the default" do
    assert Design.validate("bench") == "bench"
    assert Design.validate("soft") == "soft"
    assert Design.validate("nope") == "orbit"
    assert Design.validate(nil) == "orbit"
  end

  test "validate_mode/1 accepts only light/dark, else nil (design's native mode)" do
    assert Design.validate_mode("light") == "light"
    assert Design.validate_mode("dark") == "dark"
    assert Design.validate_mode("neon") == nil
    assert Design.validate_mode(nil) == nil
  end

  test "theme/2 combines design and mode, defaulting to the design's native mode" do
    assert Design.theme("orbit") == "orbit-dark"
    assert Design.theme("bench") == "bench-light"
    assert Design.theme("soft") == "soft-light"
    assert Design.theme("orbit", "light") == "orbit-light"
    assert Design.theme("soft", "dark") == "soft-dark"
  end

  test "name/1 and mode_name/1 return display labels" do
    assert Design.name("orbit") == "Orbit"
    assert Design.name("bench") == "Bench"
    assert Design.name("soft") == "Soft"
    assert Design.mode_name("light") == "Light"
    assert Design.mode_name("dark") == "Dark"
  end
end
