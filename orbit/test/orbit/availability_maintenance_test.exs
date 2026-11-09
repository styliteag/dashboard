defmodule Orbit.AvailabilityMaintenanceTest do
  @moduledoc """
  The maintenance flag clears only on the offline→online edge, for both
  transports (agent push and direct poll). A box that is merely still online
  keeps its flag — an operator must be able to hold a healthy agent box in
  maintenance for longer than one push interval — and a box that was offline
  and comes back has the flag cleared even when it is polled, so a forgotten
  flag no longer caps CRIT at WARN forever.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Availability

  @t0 ~N[2026-07-18 12:00:00]
  @earlier ~N[2026-07-18 11:00:00]

  describe "outcome/2" do
    for {name, success, error, expected} <- [
          {"never attempted", nil, nil, :never},
          {"success only", ~N[2026-07-18 12:00:00], nil, :online},
          {"success newer than error", ~N[2026-07-18 12:00:00], ~N[2026-07-18 11:00:00], :online},
          {"error newer than success", ~N[2026-07-18 11:00:00], ~N[2026-07-18 12:00:00],
           :offline},
          {"error only", nil, ~N[2026-07-18 12:00:00], :offline},
          {"same instant", ~N[2026-07-18 12:00:00], ~N[2026-07-18 12:00:00], :offline}
        ] do
      test name do
        assert Availability.outcome(unquote(Macro.escape(success)), unquote(Macro.escape(error))) ==
                 unquote(expected)
      end
    end
  end

  describe "maintenance_on_success/2" do
    for {prev, maintenance?, expected} <- [
          {:offline, true, :clear},
          {:offline, false, :keep},
          {:online, true, :keep},
          {:online, false, :keep},
          {:never, true, :keep},
          {:never, false, :keep}
        ] do
      test "#{prev}, maintenance=#{maintenance?} → #{expected}" do
        assert Availability.maintenance_on_success(unquote(prev), unquote(maintenance?)) ==
                 unquote(expected)
      end
    end
  end

  describe "stamp paths" do
    setup do
      group =
        Repo.insert!(%Orbit.Accounts.Group{name: "maint-#{System.unique_integer([:positive])}"})

      {:ok, group_id: group.id}
    end

    for {transport, stamp} <- [{"push", :push}, {"direct", :poll}] do
      test "#{transport}: online box keeps maintenance across a success", %{group_id: gid} do
        id = instance!(gid, unquote(transport), @t0, nil)
        stamp(unquote(stamp), id)
        assert maintenance?(id)
      end

      test "#{transport}: offline box coming back clears maintenance", %{group_id: gid} do
        id = instance!(gid, unquote(transport), @earlier, @t0)
        stamp(unquote(stamp), id)
        refute maintenance?(id)
      end

      test "#{transport}: never-seen box keeps maintenance on first contact", %{group_id: gid} do
        id = instance!(gid, unquote(transport), nil, nil)
        stamp(unquote(stamp), id)
        assert maintenance?(id)
      end
    end
  end

  defp instance!(gid, transport, success, error) do
    name = "maint-box-#{System.unique_integer([:positive])}"

    {:ok, inst} =
      Orbit.Instances.create_instance(
        %{"name" => name, "device_type" => "proxmox", "transport" => transport},
        gid
      )

    Repo.query!(
      "UPDATE instances SET maintenance = 1, last_success_at = ?, last_error_at = ? WHERE id = ?",
      [success, error, inst.id]
    )

    inst.id
  end

  defp stamp(:push, id), do: Availability.stamp_push(id, DateTime.utc_now())
  defp stamp(:poll, id), do: Availability.stamp_poll_ok(id, "box", DateTime.utc_now())

  defp maintenance?(id) do
    %{rows: [[m]]} = Repo.query!("SELECT maintenance FROM instances WHERE id = ?", [id])
    m in [1, true]
  end
end
