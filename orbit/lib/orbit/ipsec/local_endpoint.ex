defmodule Orbit.Ipsec.LocalEndpoint do
  @moduledoc """
  "Does this tunnel still pin an address the box actually has?"

  A tunnel can name a concrete local endpoint (`local` from swanctl). When
  that is a PUBLIC address it must match the box's real public address — the
  one `Orbit.ExternalIp` derives. If it does not, the tunnel is configured
  for an address the box no longer owns: it moved behind NAT, or its WAN
  address changed. Phase 1 then fails in a way whose cause is invisible in
  the tunnel's own status ("CONNECTING" forever), which is exactly why the
  retired dashboard flagged it (the `lip-mismatch` note, 2.9.10).

  Deliberately informational: no check, no alert, no notification. It is a
  hint about configuration drift, and a box can legitimately pin a public
  address it reaches through a NAT it controls.

  Only PUBLIC local endpoints are judged. A private/RFC1918 local address is
  the normal shape for a box behind NAT — comparing it to the public address
  would flag every such tunnel forever.
  """

  alias Orbit.Net

  @doc """
  `true` when the tunnel pins a public local endpoint that is not the box's
  public address.

  Returns `false` on anything uncertain: no local endpoint, a private one,
  or no known public address for the box. Never guesses.
  """
  @spec mismatch?(String.t() | nil, map()) :: boolean()
  def mismatch?(local, public_ip) when is_map(public_ip) do
    local = Net.bare_address(to_string(local || ""))
    box = public_ip[:ipv4]

    cond do
      local == "" -> false
      not Net.public_ip?(local) -> false
      is_nil(box) -> false
      true -> local != box
    end
  end

  def mismatch?(_local, _public_ip), do: false

  @doc "Hover text naming both addresses — the whole point is seeing them side by side."
  def hint(local, public_ip) do
    "This tunnel pins #{local} as its local endpoint, but the box's public " <>
      "address is #{public_ip[:ipv4]}. The box moved behind NAT, or its WAN " <>
      "address changed — phase 1 will fail without saying why."
  end
end
