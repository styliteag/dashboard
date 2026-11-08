defmodule Orbit.Capture.ParamsTokensTest do
  @moduledoc """
  Older agents split the BPF filter on whitespace into tcpdump argv, so ANY
  token starting with `-` becomes an option there — not only a leading one
  (`host 1.2.3.4 -w /tmp/x -z sh`). Refused server-side, as are non-string
  and oversized values.
  """
  use ExUnit.Case, async: true

  alias Orbit.Capture.Params

  test "an option-like token anywhere in the filter is refused" do
    for f <- ["host 10.0.0.1 -w /tmp/x", "port 443\t-z sh", "tcp and -C1"],
        do: assert({:error, _} = Params.validate("em0", f), f)
  end

  test "arithmetic minus and ordinary filters still pass" do
    for f <- ["ip[2:2] - 20 > 0", "tcp[13]&2!=0", "not host 10.0.0.1 and port 53"],
        do: assert(:ok = Params.validate("em0", f), f)
  end

  test "non-string or oversized values are refused, not crashed on" do
    assert {:error, _} = Params.validate(%{}, "")
    assert {:error, _} = Params.validate("em0", ["x"])
    assert {:error, _} = Params.validate("em0", String.duplicate("a ", 600))
  end
end
