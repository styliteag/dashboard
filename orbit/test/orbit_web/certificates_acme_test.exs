defmodule OrbitWeb.CertificatesAcmeTest do
  @moduledoc """
  ACME renewal-overdue derivation — the strongest "Let's Encrypt renewal is
  failing here" signal, restored from the retired stack (python
  views/routes.py `_ACME_ISSUER_MARKERS` + `_CERT_ACME_RENEW_DAYS`).
  """

  use ExUnit.Case, async: true

  alias OrbitWeb.CertificatesLive, as: Certs

  test "real ACME issuers are recognised" do
    assert Certs.acme?("C=US, O=Let's Encrypt, CN=R11")
    assert Certs.acme?("O=ISRG, CN=ISRG Root X1")
    assert Certs.acme?("O=ZeroSSL")
    assert Certs.acme?("O=Google Trust Services LLC")
    assert Certs.acme?("O=Buypass AS-983163327")
  end

  test "a self-signed firewall cert is not ACME" do
    refute Certs.acme?("O = pfSense GUI default Self-Signed Certificate, CN = pfSense-6865742")
    refute Certs.acme?("CN=OPNsense.internal, O=OPNsense self-signed web certificate")
    refute Certs.acme?(nil)
  end

  test "overdue only inside the renewal window, and only for ACME issuers" do
    le = "C=US, O=Let's Encrypt, CN=R11"

    # ACME renews at 30 days; still standing at 15 ⇒ the automation failed.
    assert Certs.acme_overdue?(le, 15)
    assert Certs.acme_overdue?(le, 0)

    # Outside the window it is simply a healthy certificate.
    refute Certs.acme_overdue?(le, 45)

    # Already expired reads as expired — the louder verdict wins.
    refute Certs.acme_overdue?(le, -3)

    # Nothing renews a self-signed cert automatically, so it is never overdue.
    refute Certs.acme_overdue?("O = pfSense GUI default Self-Signed Certificate", 15)

    # Missing data must not produce a verdict.
    refute Certs.acme_overdue?(le, nil)
  end
end
