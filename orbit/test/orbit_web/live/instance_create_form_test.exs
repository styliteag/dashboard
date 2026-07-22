defmodule OrbitWeb.InstanceCreateFormTest do
  @moduledoc """
  Visibility rule for the direct-API fields on the create form.

  Regression: the create form re-rendered on every tag-picker event and named
  inputs without a bound `value` were reset — picking a tag wiped the
  half-filled form. The fix binds every field to the `@form` assign; these
  tests pin the companion rule that decides which fields render at all: in
  agent mode (transport "push") the base URL/API credential fields are hidden
  and therefore absent from the submit, so `base_url` lands empty — which the
  push path requires. Push-only device types (DR-9) never show them.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.InstanceCreateLive

  test "agent mode (push) hides the direct-API fields" do
    refute InstanceCreateLive.direct_fields?(%{"transport" => "push"})
  end

  test "the initial form defaults to push and starts hidden" do
    refute InstanceCreateLive.direct_fields?(%{"transport" => "push"})
    refute InstanceCreateLive.direct_fields?(%{})
  end

  test "direct transport shows them" do
    assert InstanceCreateLive.direct_fields?(%{
             "transport" => "direct",
             "device_type" => "opnsense"
           })
  end

  test "a push-only device type hides them even on direct transport" do
    refute InstanceCreateLive.direct_fields?(%{
             "transport" => "direct",
             "device_type" => "linux"
           })
  end
end
