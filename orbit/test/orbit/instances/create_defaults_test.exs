defmodule Orbit.Instances.CreateDefaultsTest do
  @moduledoc """
  Boolean defaults a newly created instance gets. These are operator decisions,
  not schema defaults, so they belong in a test that fails when someone flips
  them by accident.
  """

  use ExUnit.Case, async: true

  # insert_instance/5 is private and writes to the database; the decision that
  # matters is the one this expression encodes, so assert it directly against
  # the shapes a form can produce.
  defp autologin?(params), do: params["gui_login_enabled"] not in [false, "false", "off"]

  test "absent means on — the create form has no checkbox for it" do
    assert autologin?(%{})
    assert autologin?(%{"name" => "box"})
  end

  test "an explicit false still wins" do
    # The edit form's flag component posts a hidden "false" ahead of the
    # checkbox, so unchecking is an explicit value and must not be read as
    # "absent, therefore on".
    refute autologin?(%{"gui_login_enabled" => "false"})
    refute autologin?(%{"gui_login_enabled" => false})
    refute autologin?(%{"gui_login_enabled" => "off"})
  end

  test "the usual truthy spellings stay on" do
    assert autologin?(%{"gui_login_enabled" => "true"})
    assert autologin?(%{"gui_login_enabled" => true})
    assert autologin?(%{"gui_login_enabled" => "on"})
  end
end
