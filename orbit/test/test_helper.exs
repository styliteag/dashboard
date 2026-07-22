# capture_log: buffer each test's Logger output and print it only when that
# test FAILS. The suite deliberately exercises error paths (geoip denials,
# failed notifies, unreachable-DB degradation, …) whose warnings/errors are
# expected — printing them inline made a green run look broken.
ExUnit.start(capture_log: true)
Ecto.Adapters.SQL.Sandbox.mode(Orbit.Repo, :manual)
