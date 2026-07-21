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

  Two things keep the hint honest:

  - **An established tunnel can never drift.** You cannot hold a live IKE SA
    from a local address the box does not currently own, so an up tunnel has
    already proven ownership — flagging "phase 1 will fail" on it is
    self-contradictory. Only DOWN tunnels are judged. (Regression: a
    Securepoint carrying several public IPs showed drift on established
    tunnels bound to a public address other than the box's first one.)
  - **A box can own MORE than one public address.** The verdict compares the
    endpoint against every public address the box is known to own — its
    derived public IP *and* any public address configured on an interface —
    not a single "the" public IP. On a box with a WAN block, the first
    interface address is an arbitrary pick; matching only it false-flagged
    every tunnel bound to a sibling address.
  """

  alias Orbit.Net

  # Status strings that mean the tunnel is up (mirrors the ipsec check family
  # and the VPN page's @ipsec_up). An up tunnel owns its local address.
  @up_states ~w(established installed connected up 1 true yes)

  @doc """
  `true` when a DOWN tunnel pins a public local endpoint the box does not own.

  Returns `false` on anything uncertain: an established tunnel, no local
  endpoint, a private one, or no known public address for the box. Never
  guesses.
  """
  @spec mismatch?(String.t() | nil, String.t() | nil, map()) :: boolean()
  def mismatch?(local, status, public_ip) when is_map(public_ip) do
    local = Net.bare_address(to_string(local || ""))

    cond do
      up?(status) -> false
      local == "" -> false
      not Net.public_ip?(local) -> false
      true -> not owns_public?(public_ip, local)
    end
  end

  def mismatch?(_local, _status, _public_ip), do: false

  defp up?(status), do: String.downcase(to_string(status || "")) in @up_states

  # Does the box own `local` as one of its public addresses? An empty owned
  # set means we don't know the box's public address, so we never guess (the
  # returned `true` becomes `false` mismatch via the `not` at the call site).
  defp owns_public?(public_ip, local) do
    owned = box_public_addresses(public_ip)
    owned == [] or local in owned
  end

  defp box_public_addresses(public_ip) do
    [public_ip[:ipv4] | List.wrap(public_ip[:interface_addresses])]
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&Net.bare_address/1)
    |> Enum.filter(&Net.public_ip?/1)
    |> Enum.uniq()
  end

  @doc "Hover text naming both addresses — the whole point is seeing them side by side."
  def hint(local, public_ip) do
    "This tunnel pins #{local} as its local endpoint, but the box's public " <>
      "address is #{public_ip[:ipv4]}. The box moved behind NAT, or its WAN " <>
      "address changed — phase 1 will fail without saying why."
  end
end
