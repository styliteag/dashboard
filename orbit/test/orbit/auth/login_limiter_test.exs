defmodule Orbit.Auth.LoginLimiterTest do
  use ExUnit.Case, async: true

  alias Orbit.Auth.LoginLimiter

  @minute 60 * 1000

  setup do
    server = start_supervised!({LoginLimiter, name: nil})
    %{server: server}
  end

  test "locks after 5 failures inside the window, is_locked reflects it", %{server: s} do
    for n <- 1..4 do
      refute LoginLimiter.record_failure(s, "10.0.0.1", n * 1000)
    end

    assert LoginLimiter.record_failure(s, "10.0.0.1", 5000), "5th failure triggers the lock"
    assert LoginLimiter.locked?(s, "10.0.0.1", 6000)
    refute LoginLimiter.locked?(s, "10.0.0.2", 6000), "other IPs unaffected"
  end

  test "lock expires after 15 minutes", %{server: s} do
    for n <- 1..5, do: LoginLimiter.record_failure(s, "10.0.0.1", n * 1000)
    assert LoginLimiter.locked?(s, "10.0.0.1", 5000 + 15 * @minute - 1)
    refute LoginLimiter.locked?(s, "10.0.0.1", 5000 + 15 * @minute + 1)
  end

  test "failures outside the 15-minute window do not count", %{server: s} do
    for n <- 1..4, do: LoginLimiter.record_failure(s, "10.0.0.1", n * 1000)
    # 5th failure arrives after the first four fell out of the window.
    refute LoginLimiter.record_failure(s, "10.0.0.1", 4000 + 15 * @minute + 1)
    refute LoginLimiter.locked?(s, "10.0.0.1", 4000 + 15 * @minute + 2)
  end

  test "success clears all state for the IP", %{server: s} do
    for n <- 1..4, do: LoginLimiter.record_failure(s, "10.0.0.1", n * 1000)
    LoginLimiter.record_success(s, "10.0.0.1")
    refute LoginLimiter.record_failure(s, "10.0.0.1", 5000), "counter starts fresh"
  end

  test "an existing lock is not re-triggered by further failures (python parity)", %{server: s} do
    for n <- 1..5, do: LoginLimiter.record_failure(s, "10.0.0.1", n * 1000)
    refute LoginLimiter.record_failure(s, "10.0.0.1", 6000), "already locked → no NEW lock signal"
  end

  test "regression: negative monotonic clock must not lock on the first failure" do
    # System.monotonic_time/1 is negative on a fresh BEAM. With locked_until
    # initialised to 0 instead of nil, `0 > negative_now` read as locked and
    # the very first bad password 429'd the IP (found in the live curl E2E).
    server = start_supervised!({LoginLimiter, name: nil}, id: :neg_clock)
    now = -576_460_751_000
    refute LoginLimiter.record_failure(server, "10.0.0.9", now)
    refute LoginLimiter.locked?(server, "10.0.0.9", now + 10)
  end
end
