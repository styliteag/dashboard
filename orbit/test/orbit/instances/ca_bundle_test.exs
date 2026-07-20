defmodule Orbit.Instances.CaBundleTest do
  @moduledoc """
  The stored CA bundle, from the audit allowlist to the TLS transport options.

  The column has existed since the python stack and the dialog offered the
  field, but orbit wrote it nowhere and read it nowhere — the only way to poll
  a box with a self-signed certificate was to switch verification off.
  """

  use ExUnit.Case, async: true

  alias Orbit.Instances
  alias Orbit.Net.TLS

  # A real (throwaway) self-signed certificate, so pem_decode has something
  # genuine to chew on rather than a shape the parser might accept by luck.
  @pem """
  -----BEGIN CERTIFICATE-----
  MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
  DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
  EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
  7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
  5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
  BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
  NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
  Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
  6MF9+Yw1Yy0t
  -----END CERTIFICATE-----
  """

  describe "audit redaction" do
    test "a PEM is recorded by name only, never by value" do
      # @editable_fields is copied VERBATIM into the audit detail, so putting
      # ca_bundle there would write the whole certificate into a table admins
      # and superadmins can read (invariant 3; the retired stack's own rule).
      detail = Instances.safe_audit_detail(%{"ca_bundle" => @pem, "name" => "pf1"})

      assert detail["secrets_rotated"] == ["ca_bundle"]
      assert detail["name"] == "pf1"
      refute Map.has_key?(detail, "ca_bundle")
      refute detail |> inspect() |> String.contains?("BEGIN CERTIFICATE")
    end

    test "an untouched bundle is not reported as rotated" do
      detail = Instances.safe_audit_detail(%{"ca_bundle" => "", "name" => "pf1"})
      refute Map.has_key?(detail, "secrets_rotated")
    end
  end

  describe "transport options" do
    test "a bundle pins verification to its certificates" do
      assert [verify: :verify_peer, cacerts: [der]] = TLS.bundle_opts(@pem)
      assert is_binary(der)
    end

    test "no usable bundle returns nil so each client keeps its own default" do
      # The two poll clients disagree on what no-bundle means (one passes no
      # verify option at all, the other asks for verify_peer). Normalising
      # them here would change how one of them reaches every box.
      assert TLS.bundle_opts(nil) == nil
      assert TLS.bundle_opts("") == nil
      assert TLS.bundle_opts("   \n ") == nil
    end

    test "a malformed bundle degrades instead of breaking the poll" do
      # One bad paste must not stop a box from being polled — failing closed
      # would take it offline for a reason no error message explains.
      assert TLS.bundle_opts("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----") ==
               nil

      assert TLS.bundle_opts("just some text") == nil
      assert TLS.cacerts(%{}) == []
    end
  end
end
