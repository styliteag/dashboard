defmodule Orbit.Settings.RegistryTest do
  use ExUnit.Case, async: true

  alias Orbit.Settings.Registry

  describe "coerce/2 — python coerce_value parity" do
    test "int parses, trims and range-checks" do
      {:ok, defn} = Registry.fetch("poll_interval_seconds")
      assert {:ok, 30} = Registry.coerce(defn, " 30 ")
      assert {:error, msg} = Registry.coerce(defn, "abc")
      assert msg =~ "must be an integer"
      assert {:error, msg} = Registry.coerce(defn, "4")
      assert msg =~ "must be ≥ 5"
      assert {:error, msg} = Registry.coerce(defn, "86401")
      assert msg =~ "must be ≤ 86400"
    end

    test "int rejects trailing garbage instead of truncating" do
      {:ok, defn} = Registry.fetch("poll_interval_seconds")
      assert {:error, _} = Registry.coerce(defn, "30x")
      assert {:error, _} = Registry.coerce(defn, "30.5")
    end

    test "bool accepts the python truthy/falsy token sets" do
      defn = %Orbit.Settings.Def{key: "x", type: :bool, env: "X", default: "false"}

      for raw <- ~w(1 true YES on) do
        assert {:ok, true} = Registry.coerce(defn, raw)
      end

      for raw <- ~w(0 false No OFF) do
        assert {:ok, false} = Registry.coerce(defn, raw)
      end

      assert {:error, msg} = Registry.coerce(defn, "maybe")
      assert msg =~ "must be a boolean"
    end

    test "str honours the options whitelist" do
      defn = %Orbit.Settings.Def{key: "x", type: :str, env: "X", default: "a", options: ~w(a b)}
      assert {:ok, "b"} = Registry.coerce(defn, "b")
      assert {:error, msg} = Registry.coerce(defn, "c")
      assert msg =~ "must be one of a, b"
    end
  end

  test "unknown keys are not editable" do
    assert :error = Registry.fetch("database_url")
    assert :error = Registry.fetch("master_key")
  end
end

defmodule Orbit.SettingsWriteTest do
  @moduledoc "DB-free error paths of set/clear_override; the :ok DB path is proven live."
  use ExUnit.Case, async: true

  test "set_override on an unknown key errors before any DB write" do
    assert {:error, msg} = Orbit.Settings.set_override("not_a_key", "5")
    assert msg =~ "not an editable setting"
  end

  test "set_override with an invalid value errors on coercion (no DB write)" do
    assert {:error, msg} = Orbit.Settings.set_override("poll_interval_seconds", "abc")
    assert msg =~ "must be an integer"
  end

  test "clear_override on an unknown key errors" do
    assert {:error, _} = Orbit.Settings.clear_override("not_a_key")
  end
end
