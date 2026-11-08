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

  # Python's str.split() (old agents) also splits on \x1c-\x1f, U+00A0,
  # U+202F and other Unicode spaces that Elixir's String.split/1 keeps inside
  # a token — so `-w` hidden behind such a separator slipped past the token
  # check. Only printable ASCII without quotes or backslashes is accepted.
  test "separators Python splits on but Elixir does not are refused" do
    for sep <- ["\x1c", "\x1d", "\x1e", "\x1f", "\u00a0", "\u202f", "\u2003", "\u3000"] do
      f = "host 1.2.3.4" <> sep <> "-w" <> sep <> "/tmp/x" <> sep <> "-z" <> sep <> "/bin/sh"
      assert {:error, _} = Params.validate("em0", f), inspect(f)
    end
  end

  test "quotes, backslashes and control characters are refused" do
    for f <- [
          ~s(host 1.2.3.4 "-w" /tmp/x),
          "host 1.2.3.4 '-w' /tmp/x",
          "host 1.2.3.4 \\-w /tmp/x",
          "host 1.2.3.4\n-w /tmp/x",
          "host 1.2.3.4\r-w",
          "host\x00-w",
          "host 1.2.3.4\x7f"
        ],
        do: assert({:error, _} = Params.validate("em0", f), inspect(f))
  end

  test "non-string or oversized values are refused, not crashed on" do
    assert {:error, _} = Params.validate(%{}, "")
    assert {:error, _} = Params.validate("em0", ["x"])
    assert {:error, _} = Params.validate("em0", String.duplicate("a ", 600))
  end
end
