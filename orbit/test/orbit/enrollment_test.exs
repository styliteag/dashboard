defmodule Orbit.EnrollmentTest do
  @moduledoc "Code hashing + parity checks (redeem's DB path is covered by the live E2E)."
  use ExUnit.Case, async: true

  alias Orbit.Enrollment

  test "hash_code is a lowercase hex sha256, deterministic" do
    h = Enrollment.hash_code("abc")
    assert h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert Enrollment.hash_code("abc") == h
    refute Enrollment.hash_code("abd") == h
  end

  test "distinct codes hash distinctly (only the hash is stored)" do
    assert Enrollment.hash_code("code-1") != Enrollment.hash_code("code-2")
  end
end
