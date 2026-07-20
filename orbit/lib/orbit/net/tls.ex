defmodule Orbit.Net.TLS do
  @moduledoc """
  Transport options for an outbound poll to a firewall's API.

  A firewall's web GUI carries a self-signed certificate, so the honest
  choices are "verify against the CA that signed it" or "do not verify".
  Instances have carried a `ca_bundle` column since the python stack and the
  edit dialog offered a "CA bundle (PEM)" field, but orbit consumed neither:
  the column was written by nothing and read by nothing, so the only way to
  poll a box was to switch verification OFF entirely. This makes the stored
  bundle mean something again.

  Three cases, and only the third is new behaviour:

  - verification off → the client's own `verify_none`, bundle never parsed
  - verification on, no bundle → whatever that client did before, untouched
  - verification on, bundle present → verify against THAT bundle

  A malformed bundle degrades to the no-bundle case rather than raising: one
  bad paste must not stop a box from being polled, and failing closed here
  would take the box offline for a reason no error message would explain.
  """

  require Logger

  @doc """
  `transport_opts` pinning verification to this bundle, or nil when there is
  no usable bundle and the caller should keep its own default.

  Returning nil rather than a "sensible" default is deliberate: the two poll
  clients do NOT agree on what no-bundle means (the OPNsense client passes no
  verify option at all and inherits the HTTP stack's trust store, the
  Securepoint one asks for `verify_peer` explicitly). Normalising them here
  would silently change how one of them connects to every box in the fleet,
  which is not what wiring up a new field should do.
  """
  @spec bundle_opts(String.t() | nil) :: keyword() | nil
  def bundle_opts(bundle) do
    case cacerts(bundle) do
      [] -> nil
      ders -> [verify: :verify_peer, cacerts: ders]
    end
  end

  @doc "DER certificates from a PEM bundle; [] for nil, blank or unparseable."
  @spec cacerts(String.t() | nil) :: [binary()]
  def cacerts(bundle) when is_binary(bundle) do
    case String.trim(bundle) do
      "" ->
        []

      pem ->
        for {type, der, _cipher} <- :public_key.pem_decode(pem),
            type in [:Certificate, :OTPCertificate],
            do: der
    end
  rescue
    error ->
      Logger.warning("tls.ca_bundle_unparseable error=#{Exception.message(error)}")
      []
  end

  def cacerts(_bundle), do: []
end
