"""Standalone connectivity ping monitors (tunnel-independent source→dest probes).

Mirrors the IPsec Phase-2 ping feature but without any tunnel/child binding: a
per-instance (source, destination) pair the agent pings on the firewall each push
cycle. Results flow back in the metrics push keyed by row id and become
``connectivity:<id>`` ServiceChecks, so they alert channels and export to Checkmk
the same way every other check does.
"""
