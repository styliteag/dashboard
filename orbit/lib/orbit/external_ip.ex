defmodule Orbit.ExternalIp do
  @moduledoc """
  "Where does this box sit on the internet?" — one answer shape for every
  transport (ExternalIpSection.tsx port, widened past the agent).

  The old dashboard only answered this for agent-push boxes, because only
  the agent runs the ipify probe. A direct-polled OPNsense/pfSense and a
  Securepoint report their interface addresses just the same, and a routable
  address configured on an interface *is* the box's public address — so the
  question is answerable for the whole fleet, with the source labelled so an
  operator can tell a probe from an inference.

  Sources, in the order they are preferred:

  - `:probe` — the agent's ipify echo (`external_ip` section). Authoritative:
    it is what the outside world actually sees, NAT or not.
  - `:interface` — a globally routable address configured on one of the box's
    own interfaces. True for a firewall that owns its WAN address; this is
    the only source a poll-mode box has.

  NAT verdict (IPv4 only — the interface data is the only cross-check we
  have and it is what the python version judged on):

  - the public IPv4 is one of the box's own interface addresses → `:direct`
  - it is not → `:behind_nat` (an upstream NAT owns the address)
  - no public IPv4 known at all → `:unknown`, never a guess

  Pure: takes the already-loaded hub/poll snapshot, returns a map. No
  queries, no probing, nothing that could block a render.
  """

  alias Orbit.Net

  @type source :: :probe | :interface | nil
  @type nat :: :direct | :behind_nat | :unknown

  @doc """
  Build the public-IP view for one instance.

  `entry` is the hub cache entry (agent push) or the poll snapshot — both
  carry `status.interfaces`, and only the agent carries `external_ip`.
  `source_ip` is the peer address the hub saw when the agent connected
  (nil for poll-mode boxes: they never connect *to* us).
  """
  @spec build(map(), keyword()) :: map()
  def build(entry, opts \\ []) when is_map(entry) do
    source_ip = Keyword.get(opts, :source_ip)
    connected? = Keyword.get(opts, :connected, false)

    probe = probe_addresses(entry)
    iface_addrs = interface_addresses(entry)

    ipv4 = probe[:ipv4] || public_v4(iface_addrs)
    ipv6 = probe[:ipv6] || public_v6(iface_addrs)

    %{
      ipv4: ipv4,
      ipv6: ipv6,
      source: address_source(probe, ipv4, ipv6),
      checked_at: probe[:checked_at],
      source_ip: source_ip,
      connected: connected?,
      nat: nat_verdict(ipv4, iface_addrs),
      interface_addresses: iface_addrs
    }
  end

  @doc "Is there anything worth rendering? (hide the block rather than show blanks)"
  def known?(%{ipv4: nil, ipv6: nil, source_ip: nil}), do: false
  def known?(%{}), do: true

  # -- sources ---------------------------------------------------------------

  defp probe_addresses(entry) do
    case entry["external_ip"] do
      ext when is_map(ext) ->
        %{
          ipv4: presence(ext["ipv4"]),
          ipv6: presence(ext["ipv6"]),
          checked_at: presence(ext["checked_at"])
        }

      _ ->
        %{}
    end
  end

  @doc """
  Every address the box reports on its own interfaces.

  Agent and Securepoint report one address per interface (`address`); the
  OPNsense poller additionally carries the full per-interface list in
  `addresses`, because OPNsense reports an interface once per configured
  address and only that list contains the aliases.
  """
  def interface_addresses(entry) do
    entry
    |> get_in(["status", "interfaces"])
    |> List.wrap()
    |> Enum.flat_map(fn
      iface when is_map(iface) ->
        List.wrap(iface["addresses"]) ++ List.wrap(iface["address"])

      _ ->
        []
    end)
    |> Enum.filter(&is_binary/1)
    # Devices decorate addresses differently (Securepoint sends a CIDR
    # prefix, IPv6 rows an interface zone) and mix MACs into the same field
    # — compare bare, parseable addresses only.
    |> Enum.filter(&Net.ip_address?/1)
    |> Enum.map(&Net.bare_address/1)
    |> Enum.uniq()
  end

  defp address_source(probe, ipv4, ipv6) do
    cond do
      probe[:ipv4] || probe[:ipv6] -> :probe
      ipv4 || ipv6 -> :interface
      true -> nil
    end
  end

  defp public_v4(addrs), do: Enum.find(addrs, &(v4?(&1) and Net.public_ip?(&1)))
  defp public_v6(addrs), do: Enum.find(addrs, &(not v4?(&1) and Net.public_ip?(&1)))

  # -- NAT -------------------------------------------------------------------

  # No public IPv4 to reason about ⇒ say so. A box whose only addresses are
  # private may well sit behind NAT, but without its public address that is
  # an assumption, and the old UI's rule was "never guess".
  defp nat_verdict(nil, _iface_addrs), do: :unknown

  defp nat_verdict(_ipv4, []), do: :unknown

  defp nat_verdict(ipv4, iface_addrs) do
    if ipv4 in iface_addrs, do: :direct, else: :behind_nat
  end

  defp v4?(addr), do: not String.contains?(addr, ":")

  defp presence(v) when is_binary(v) do
    case String.trim(v) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp presence(_), do: nil
end
