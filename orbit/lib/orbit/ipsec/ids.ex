defmodule Orbit.Ipsec.Ids do
  @moduledoc """
  Format checks for IPsec ids that arrive from the DOM: the tunnel
  (connection) id and the IKE_SA unique id. Both become `swanctl` argv on the
  box (agent, as root) or part of the Securepoint SSH diagnose script.

  Tunnel ids: strongSwan connection names, OPNsense uuids and Securepoint's
  `$xx`-escaped section names (`OCV$20MEH`) — letters, digits and `._:$-`,
  never a leading `-`. Unique ids are swanctl's numeric `uniqueid`.
  """

  @tunnel ~r/\A[A-Za-z0-9._:$][A-Za-z0-9._:$-]{0,127}\z/
  @unique ~r/\A[0-9]{0,10}\z/

  @spec tunnel_id?(term()) :: boolean()
  def tunnel_id?(v), do: is_binary(v) and Regex.match?(@tunnel, v)

  @doc "Digits, or blank (no live SA)."
  @spec unique_id?(term()) :: boolean()
  def unique_id?(v), do: is_binary(v) and Regex.match?(@unique, v)
end
