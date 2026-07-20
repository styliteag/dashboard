defmodule OrbitWeb.Components.TagPickerTest do
  @moduledoc "Picker list logic (TagsInput.tsx parity) — DB-free."
  use ExUnit.Case, async: true

  alias OrbitWeb.Components.TagPicker

  describe "add/2" do
    test "appends a trimmed tag" do
      assert TagPicker.add(["LAB"], "  customer-x  ") == ["LAB", "customer-x"]
    end

    test "blank input is a no-op" do
      assert TagPicker.add(["LAB"], "   ") == ["LAB"]
    end

    test "duplicate guard is case-insensitive" do
      # The fleet page filters tags on exact matches, so "LAB" and "lab" would
      # be two chips for one thing.
      assert TagPicker.add(["LAB"], "lab") == ["LAB"]
    end

    test "a known tag typed in another case adopts the fleet's spelling" do
      # Same reason one level up: "lab" next to the fleet's "LAB" is a second
      # tag that looks like the first one.
      assert TagPicker.add([], "lab", ["LAB", "prod"]) == ["LAB"]
    end

    test "an unknown tag keeps the typed spelling" do
      assert TagPicker.add([], "Site-7", ["LAB"]) == ["Site-7"]
    end
  end

  describe "remove/2 and drop_last/1" do
    test "remove takes the named chip" do
      assert TagPicker.remove(["a", "b", "c"], "b") == ["a", "c"]
    end

    test "drop_last eats the last chip and tolerates an empty list" do
      assert TagPicker.drop_last(["a", "b"]) == ["a"]
      assert TagPicker.drop_last([]) == []
    end

    test "backspace in an empty field eats the last chip" do
      assert TagPicker.backspace(["a", "b"], "") == ["a"]
    end

    test "backspace that only clears typed text leaves the chips alone" do
      # phx-keyup reports the value AFTER the key, so deleting the last
      # character looks exactly like backspace on an empty field. Judged on
      # the previous query, this one was still "x" — no chip may be lost.
      assert TagPicker.backspace(["a", "b"], "x") == ["a", "b"]
    end
  end

  describe "options/3" do
    test "empty query offers every unpicked known tag" do
      assert TagPicker.options(["LAB", "prod"], ["LAB"], "") == [{:existing, "prod"}]
    end

    test "typed text filters by substring, case-insensitively" do
      assert TagPicker.options(["customer-x", "prod"], [], "CUST") ==
               [{:existing, "customer-x"}, {:create, "CUST"}]
    end

    test "an exact known tag offers no create entry" do
      assert TagPicker.options(["prod"], [], "prod") == [{:existing, "prod"}]
    end

    test "an unknown word is creatable" do
      assert TagPicker.options(["prod"], [], "new-site") == [{:create, "new-site"}]
    end

    test "an already picked tag is neither listed nor creatable" do
      assert TagPicker.options(["prod"], ["prod"], "prod") == []
    end

    test "the list is capped so the dropdown never becomes a scroll wall" do
      known = for n <- 1..20, do: "tag#{n}"
      assert length(TagPicker.options(known, [], "")) == 8
    end
  end
end
