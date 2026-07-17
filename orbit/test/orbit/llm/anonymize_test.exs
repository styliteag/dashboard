defmodule Orbit.LLM.AnonymizeTest do
  @moduledoc "Cross-language parity vs backend/src/app/llm/anonymize.py (vectors from the python fn)."
  use ExUnit.Case, async: true

  alias Orbit.LLM.Anonymize

  # {input, expected} — expected produced by running anonymize() in the python backend.
  @vectors [
    {"conn from 8.8.8.8 to 10.0.0.5 dev em0", "conn from PUBIP1 to 10.0.0.5 dev em0"},
    {"user root login from 203.0.113.9 and 192.168.1.1",
     "user root login from 203.0.113.9 and 192.168.1.1"},
    {"mac aa:bb:cc:dd:ee:ff seen; gw 1.1.1.1", "mac 00:00:00:00:ee:ff seen; gw PUBIP1"},
    {"password: hunter2 and api_key=DEADBEEF token bearer abc.def",
     "password: REDACTED and api_key=REDACTED token REDACTED HOST1"},
    {"host firewall.example.com pinged filter.log rotated",
     "host HOST1 pinged filter.log rotated"},
    {"v6 2606:4700:4700::1111 and fe80::1 and fc00::1 and ::1",
     "v6 PUBIP6_1 and fe80::1 and fc00::1 and ::1"},
    {"dup 9.9.9.9 then 9.9.9.9 again and 8.8.4.4", "dup PUBIP1 then PUBIP1 again and PUBIP2"},
    {"cgnat 100.64.0.1 testnet 198.51.100.7 linklocal 169.254.0.1",
     "cgnat 100.64.0.1 testnet 198.51.100.7 linklocal 169.254.0.1"},
    {"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----", "REDACTED"},
    {"mixed host a.b.co.uk ip 45.83.1.2 priv 172.16.5.5",
     "mixed host HOST1 ip PUBIP1 priv 172.16.5.5"}
  ]

  test "matches the python anonymizer on every vector" do
    for {input, expected} <- @vectors do
      assert Anonymize.anonymize(input) == expected, "mismatch for: #{inspect(input)}"
    end
  end

  test "is deterministic and correlates repeated tokens" do
    out = Anonymize.anonymize("a 8.8.8.8 b 8.8.8.8 c 1.1.1.1")
    assert out == "a PUBIP1 b PUBIP1 c PUBIP2"
    assert out == Anonymize.anonymize("a 8.8.8.8 b 8.8.8.8 c 1.1.1.1")
  end
end
