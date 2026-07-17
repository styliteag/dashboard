defmodule Orbit.Instances.SlugTest do
  @moduledoc "instances/slug.py port — german digraphs, accents, dns-label rules."

  use ExUnit.Case, async: true

  alias Orbit.Instances.Slug

  test "german digraphs map before accent stripping (ü keeps its e)" do
    assert Slug.slugify("Büro-FW") == "buero-fw"
    assert Slug.slugify("Größe ß") == "groesse-ss"
  end

  test "accents strip, separators collapse, edges trim" do
    assert Slug.slugify("Café  Zentrale!") == "cafe-zentrale"
    assert Slug.slugify("--x--") == "x"
  end

  test "empty input falls back, long input truncates without a trailing hyphen" do
    assert Slug.slugify("!!!") == "fw"
    long = String.duplicate("a", 62) <> "-bbb"
    slug = Slug.slugify(long)
    assert String.length(slug) <= Slug.max_len()
    refute String.ends_with?(slug, "-")
  end

  test "valid? enforces the dns-label shape" do
    assert Slug.valid?("fw-01")
    refute Slug.valid?("-fw")
    refute Slug.valid?("fw_01")
    refute Slug.valid?("FW")
    refute Slug.valid?(String.duplicate("a", 64))
  end
end
