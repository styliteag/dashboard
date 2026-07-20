defmodule Orbit.Repo.MigratorTest do
  @moduledoc """
  The boot-time wait for the database. Probe and sleep are injected, so this
  exercises the retry logic with no database and no real waiting.
  """

  use ExUnit.Case, async: true

  alias Orbit.Repo.Migrator

  defp counting_sleep do
    parent = self()
    fn ms -> send(parent, {:slept, ms}) end
  end

  test "a database that is up returns immediately, without sleeping" do
    assert :ok = Migrator.await_database(probe: fn -> :ok end, sleep: counting_sleep())
    refute_received {:slept, _}
  end

  test "a database that comes up late is waited out" do
    # Swarm and Kubernetes have no depends_on, so orbit routinely starts before
    # its database resolves. Before this, the first pool checkout was dropped
    # after 4s, the supervisor could not start the migrator, the application
    # exited and the runtime wrote an erl_crash.dump — for a race that fixes
    # itself seconds later.
    {:ok, attempts} = Agent.start_link(fn -> 0 end)

    probe = fn ->
      n = Agent.get_and_update(attempts, &{&1 + 1, &1 + 1})
      if n >= 3, do: :ok, else: :nxdomain
    end

    assert :ok =
             Migrator.await_database(
               probe: probe,
               sleep: counting_sleep(),
               pause_ms: 1_000,
               budget_ms: 60_000
             )

    assert Agent.get(attempts, & &1) == 3
    assert_received {:slept, 1_000}
    assert_received {:slept, 1_000}
  end

  test "a database that never comes up raises after the budget, naming the cause" do
    # Bounded on purpose: waiting forever would hide a typo in DATABASE_URL
    # behind a container that merely looks like it is still starting.
    error =
      assert_raise RuntimeError, fn ->
        Migrator.await_database(
          probe: fn -> :nxdomain end,
          sleep: fn _ -> :ok end,
          pause_ms: 1_000,
          budget_ms: 3_000
        )
      end

    assert error.message =~ "database not reachable after 3s"
    assert error.message =~ ":nxdomain"
    assert error.message =~ "DATABASE_URL"
  end
end
