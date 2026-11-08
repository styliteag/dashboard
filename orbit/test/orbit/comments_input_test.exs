defmodule Orbit.CommentsInputTest do
  @moduledoc """
  Comment writes are bounded strings: text at most 10 000 characters,
  entity_key within its 255-character column, no non-string values.
  Refused before the DB (no truncation, no crash).
  """
  use ExUnit.Case, async: true

  alias Orbit.Comments

  test "overlong or non-string text is refused" do
    assert {:error, :invalid} =
             Comments.upsert(1, "tunnel", "k", String.duplicate("a", 10_001), "u")

    assert {:error, :invalid} = Comments.upsert(1, "tunnel", "k", %{"x" => 1}, "u")
  end

  test "overlong or non-string entity_key is refused" do
    assert {:error, :invalid} = Comments.upsert(1, "tunnel", String.duplicate("k", 256), "t", "u")
    assert {:error, :invalid} = Comments.upsert(1, "tunnel", ["k"], "t", "u")
  end

  test "valid_input?/2 is the shared check" do
    assert Comments.valid_input?("k", "text")
    refute Comments.valid_input?("k", String.duplicate("a", 10_001))
  end
end
