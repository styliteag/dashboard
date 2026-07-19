defmodule Orbit.Checks.ExportTest do
  @moduledoc """
  Checkmk export shaping (routes.py export_checkmk parity): selection filter
  with base-default OFF, aggregation after selection, blackout shape.
  """
  use ExUnit.Case, async: true

  alias Orbit.Checks.{Export, ServiceCheck}

  defp inst(id, name), do: %{id: id, name: name, device_type: "opnsense", mode: "push"}

  defp check(key, state \\ 0),
    do: %ServiceCheck{key: key, state: state, summary: key, metrics: []}

  test "base default OFF: no selection rule exports no checks" do
    body = Export.checkmk_body([{inst(1, "opn1"), [check("cpu")]}], fn _k, _i -> false end, false)

    assert %{version: 1, instances: [%{instance_id: 1, name: "opn1", host: "opn1", checks: []}]} =
             body
  end

  test "selection filter is per check key and instance" do
    selected? = fn key, iid -> key == "cpu" and iid == 1 end

    pairs = [
      {inst(1, "opn1"), [check("cpu"), check("memory")]},
      {inst(2, "opn2"), [check("cpu")]}
    ]

    assert %{instances: [%{checks: [%{key: "cpu"}]}, %{checks: []}]} =
             Export.checkmk_body(pairs, selected?, false)
  end

  test "aggregate collapses after selection, so aggregates reflect exported checks" do
    # Selection drops cert:vpn; the aggregate must count only the survivor.
    selected? = fn key, _iid -> key != "cert:vpn" end
    pairs = [{inst(1, "opn1"), [check("cert:web"), check("cert:vpn", 2)]}]

    assert %{instances: [%{checks: [agg]}]} = Export.checkmk_body(pairs, selected?, true)
    assert agg.key == "certs"
    assert agg.state == 0
    assert agg.summary == "Certificates: all 1 OK"
  end

  test "checks serialize flat (key/state/summary/metrics), no envelope" do
    body =
      Export.checkmk_body(
        [
          {inst(1, "opn1"),
           [
             %ServiceCheck{
               key: "cpu",
               state: 1,
               summary: "CPU 91%",
               metrics: [ServiceCheck.metric("cpu", 91.0, warn: 90.0)]
             }
           ]}
        ],
        fn _k, _i -> true end,
        false
      )

    assert %{instances: [%{checks: [c]}]} = body

    assert c == %{
             key: "cpu",
             state: 1,
             summary: "CPU 91%",
             metrics: [%{name: "cpu", value: 91.0, warn: 90.0, crit: nil, unit: ""}]
           }
  end
end
