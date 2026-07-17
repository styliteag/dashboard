defmodule Orbit.CommentsTest do
  @moduledoc "Pure kind-allowlist guard; CRUD + scoping proven in the live E2E."
  use ExUnit.Case, async: true

  alias Orbit.Comments

  test "valid_kind? accepts exactly the four annotatable families" do
    for k <- ~w(ipsec connectivity firmware cert), do: assert(Comments.valid_kind?(k))
  end

  test "valid_kind? rejects anything else" do
    refute Comments.valid_kind?("instance")
    refute Comments.valid_kind?("")
    refute Comments.valid_kind?(nil)
  end
end
