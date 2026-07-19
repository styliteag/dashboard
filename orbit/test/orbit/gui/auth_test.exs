defmodule Orbit.GUI.AuthTest do
  @moduledoc """
  gui_auth.py wire-compatibility. The cross-language vector was produced by
  the python signer with the test master key — proving a token minted by
  either stack verifies on the other (both derive the same HMAC key).
  """

  # async: false — pins the master key via Application env (runtime.exs
  # otherwise overrides the test.exs value with the container's DASH_MASTER_KEY).
  use ExUnit.Case, async: false

  alias Orbit.GUI.Auth

  # The vector key: the same base64 string the python signer used below.
  @master_key "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
  # Python: sign_gui_token(7, exp=9999999999) with @master_key.
  @python_token "Nzo5OTk5OTk5OTk5.xdmq7ylHRotxY8GgS-QEdFHOTIVMoh5bH1wNJ8-V0CQ"

  setup do
    previous = Application.get_env(:orbit, :dash_master_key)
    Application.put_env(:orbit, :dash_master_key, @master_key)
    on_exit(fn -> Application.put_env(:orbit, :dash_master_key, previous) end)
    :ok
  end

  test "verifies a token minted by the python signer (cross-language)" do
    assert Auth.verify(@python_token, 1_000_000_000) == 7
  end

  test "round-trips through orbit's own signer" do
    token = Auth.sign(42, 3600)
    assert Auth.verify(token) == 42
  end

  test "an expired token is rejected" do
    token = Auth.sign(7, 60, 1_000)
    assert Auth.verify(token, 2_000) == nil
  end

  test "a tampered signature or payload is rejected" do
    assert Auth.verify("Nzo5OTk5OTk5OTk5.deadbeef", 1_000_000_000) == nil
    assert Auth.verify("garbage", 1_000_000_000) == nil
    assert Auth.verify("no-dot-token", 1_000_000_000) == nil
  end

  test "instance binding: the token carries its instance id" do
    assert Auth.sign(3, 60) |> Auth.verify() == 3
    refute Auth.sign(3, 60) |> Auth.verify() == 4
  end
end
