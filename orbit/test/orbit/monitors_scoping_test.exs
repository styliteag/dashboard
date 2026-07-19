defmodule Orbit.MonitorsScopingTest do
  @moduledoc """
  A forged monitor id must not reach across instances.

  The LiveViews resolve the INSTANCE through Scope.get_instance/2 (covered by
  scope_test.exs), which is the primary defence — `phx-value-*` is rendered into
  the DOM and is therefore entirely visitor-controlled. This pins the second
  layer: even holding a valid session for instance A, addressing a monitor that
  belongs to instance B must change nothing, because every statement carries
  `WHERE id = ? AND instance_id = ?`.

  Without that pairing an operator scoped to one customer could edit or delete
  another customer's monitors by guessing an id.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Monitors

  @owner 4001
  @other 4002

  setup do
    # Two instances in different groups: the monitors carry a foreign key, and
    # the point of the test is that one cannot reach the other's rows.
    Orbit.Repo.query!("INSERT IGNORE INTO `groups` (id, name) VALUES (901, ?), (902, ?)", [
      "scope-a",
      "scope-b"
    ])

    for {id, gid, name} <- [{@owner, 901, "owner"}, {@other, 902, "other"}] do
      Orbit.Repo.query!("DELETE FROM connectivity_monitors WHERE instance_id = ?", [id])
      Orbit.Repo.query!("DELETE FROM ipsec_ping_monitors WHERE instance_id = ?", [id])
      Orbit.Repo.query!("DELETE FROM instances WHERE id = ?", [id])

      Orbit.Repo.query!(
        "INSERT INTO instances (id, name, base_url, api_key_enc, api_secret_enc, slug, " <>
          "group_id, transport, device_type, created_at, updated_at) " <>
          "VALUES (?, ?, ?, '', '', ?, ?, 'direct', 'securepoint', NOW(), NOW())",
        [id, name, "https://#{name}.invalid/", name, gid]
      )
    end

    on_exit(fn ->
      for id <- [@owner, @other] do
        Orbit.Repo.query!("DELETE FROM connectivity_monitors WHERE instance_id = ?", [id])
        Orbit.Repo.query!("DELETE FROM ipsec_ping_monitors WHERE instance_id = ?", [id])
        Orbit.Repo.query!("DELETE FROM instances WHERE id = ?", [id])
      end
    end)

    :ok
  end

  defp own_monitor do
    :ok = Monitors.create_connectivity(@owner, %{"name" => "owned", "destination" => "10.0.0.1"})
    Monitors.list_connectivity(@owner) |> Enum.find(&(&1.name == "owned"))
  end

  describe "connectivity monitors" do
    test "an update addressed to the wrong instance changes nothing" do
      mon = own_monitor()

      Monitors.update_connectivity(@other, mon.id, %{
        "name" => "hijacked",
        "destination" => "1.2.3.4"
      })

      after_ = Monitors.list_connectivity(@owner) |> Enum.find(&(&1.id == mon.id))

      assert after_.name == "owned", "a foreign instance must not rename this monitor"
      assert after_.destination == "10.0.0.1"
    end

    test "a delete addressed to the wrong instance leaves it alone" do
      mon = own_monitor()

      Monitors.delete_connectivity(@other, mon.id)

      assert Monitors.list_connectivity(@owner) |> Enum.any?(&(&1.id == mon.id)),
             "a foreign instance must not delete this monitor"
    end

    test "a toggle addressed to the wrong instance leaves it alone" do
      mon = own_monitor()
      was = mon.enabled

      Monitors.toggle_connectivity(@other, mon.id)

      after_ = Monitors.list_connectivity(@owner) |> Enum.find(&(&1.id == mon.id))
      assert after_.enabled == was
    end

    test "the owning instance can of course change it" do
      mon = own_monitor()

      :ok =
        Monitors.update_connectivity(@owner, mon.id, %{
          "name" => "renamed",
          "destination" => "10.0.0.2"
        })

      after_ = Monitors.list_connectivity(@owner) |> Enum.find(&(&1.id == mon.id))
      assert after_.name == "renamed"
      assert after_.destination == "10.0.0.2"
    end
  end

  describe "ipsec phase-2 monitors" do
    test "a foreign instance can neither edit nor delete" do
      :ok =
        Monitors.create_ipsec(@owner, %{
          "tunnel_id" => "t1",
          "child_name" => "c1",
          "destination" => "10.9.9.9"
        })

      mon = Monitors.list_ipsec(@owner) |> Enum.find(&(&1.destination == "10.9.9.9"))

      Monitors.update_ipsec(@other, mon.id, %{"destination" => "1.2.3.4"})
      Monitors.delete_ipsec(@other, mon.id)

      after_ = Monitors.list_ipsec(@owner) |> Enum.find(&(&1.id == mon.id))

      assert after_, "a foreign instance must not delete this monitor"
      assert after_.destination == "10.9.9.9"
    end
  end
end
