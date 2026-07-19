defmodule Orbit.Logs.EventsTest do
  @moduledoc "Cross-language parity vs backend/src/app/logs/events.py (vectors from the python fn)."
  use ExUnit.Case, async: true

  alias Orbit.Logs.Events

  @content """
  <27>1 2026-07-17T10:00:00Z host filterlog 123 - blocked 8.8.8.8 port 22
  <27>1 2026-07-17T10:00:01Z host filterlog 124 - blocked 9.9.9.9 port 22
  Aug 13 10:00:02 fw sshd[4111]: Failed password for root from 1.2.3.4
  Aug 13 10:00:03 fw dpinger: sendto error: 55
  Aug 13 10:00:04 fw kernel: GEOM: da0: corrupt metadata
  Aug 13 10:00:05 fw check_reload_status: link state changed to DOWN
  <14>1 2026-07-17T10:00:06Z host nginx 999 - GET /ok normal line info
  Aug 13 10:00:07 fw filterdns: failed to resolve host example.org
  """

  @expected [
    %{
      severity: 3,
      program: "filterlog",
      pattern: "blocked IP port N",
      sample: "<27>1 2026-07-17T10:00:01Z host filterlog 124 - blocked 9.9.9.9 port 22",
      count: 2,
      last_ts: "2026-07-17T10:00:01Z"
    },
    %{
      severity: 3,
      program: "sshd",
      pattern: "Failed password for root from IP",
      sample: "Aug 13 10:00:02 fw sshd[4111]: Failed password for root from 1.2.3.4",
      count: 1,
      last_ts: "Aug 13 10:00:02"
    },
    %{
      severity: 3,
      program: "GEOM",
      pattern: "da0: corrupt metadata",
      sample: "Aug 13 10:00:04 fw kernel: GEOM: da0: corrupt metadata",
      count: 1,
      last_ts: "Aug 13 10:00:04"
    },
    %{
      severity: 4,
      program: "check_reload_status",
      pattern: "link state changed to DOWN",
      sample: "Aug 13 10:00:05 fw check_reload_status: link state changed to DOWN",
      count: 1,
      last_ts: "Aug 13 10:00:05"
    }
  ]

  test "extract_events matches the python extractor (aggregation, noise drop, kernel resplit, sort)" do
    # @content is a heredoc: each line carries no leading indent, trailing "\n".
    assert Events.extract_events("system.log", @content) == @expected
  end

  test "normalize collapses variable parts" do
    assert Events.normalize(~s(login from 10.0.0.1 pid 4242 "quoted")) ==
             ~s(login from IP pid N "…")
  end
end
