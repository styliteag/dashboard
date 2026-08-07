defmodule OrbitWeb.InstanceFormTest do
  @moduledoc """
  Inline-validation rules for the instance forms (UI/UX review U-M4):
  only touched fields report, and the rules mirror Orbit.Instances'
  submit-time checks.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.InstanceForm

  defp touched(fields), do: MapSet.new(fields)

  test "untouched fields never report, even when invalid" do
    assert InstanceForm.errors(%{"name" => ""}, touched([])) == %{}
  end

  test "touch/2 records the phx-change target field" do
    touched = InstanceForm.touch(MapSet.new(), %{"_target" => ["instance", "name"]})
    assert MapSet.member?(touched, "name")

    # payloads without a form target (e.g. checkbox arrays) change nothing
    assert InstanceForm.touch(touched, %{}) == touched
  end

  test "a touched empty name is required" do
    assert %{"name" => "name is required"} =
             InstanceForm.errors(%{"name" => "  "}, touched(["name"]))

    assert InstanceForm.errors(%{"name" => "pf1"}, touched(["name"])) == %{}
  end

  test "slug: blank passes, invalid label reports" do
    assert InstanceForm.errors(%{"slug" => ""}, touched(["slug"])) == %{}
    assert InstanceForm.errors(%{"slug" => "lab-fw1"}, touched(["slug"])) == %{}

    assert %{"slug" => msg} = InstanceForm.errors(%{"slug" => "Nope_"}, touched(["slug"]))
    assert msg =~ "dns label"
  end

  test "urls must carry a scheme when present" do
    for field <- ["base_url", "ping_url"] do
      assert InstanceForm.errors(%{field => ""}, touched([field])) == %{}
      assert InstanceForm.errors(%{field => "https://fw.example"}, touched([field])) == %{}

      assert %{^field => msg} = InstanceForm.errors(%{field => "fw.example"}, touched([field]))
      assert msg =~ "http"
    end
  end

  test "intervals must be positive integers when present" do
    for field <- ["push_interval_seconds", "poll_interval_seconds"] do
      assert InstanceForm.errors(%{field => ""}, touched([field])) == %{}
      assert InstanceForm.errors(%{field => "60"}, touched([field])) == %{}

      for bad <- ["0", "-5", "6.5", "abc"] do
        assert %{^field => _} = InstanceForm.errors(%{field => bad}, touched([field]))
      end
    end
  end
end
