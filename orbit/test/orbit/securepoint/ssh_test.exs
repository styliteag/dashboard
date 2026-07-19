defmodule Orbit.Securepoint.SSHTest do
  @moduledoc """
  Host-key policy and key handling for the Securepoint SSH transport.

  The connection itself is proven live (see the commit body): against a lab box
  the unpinned connect is refused, `probe_host_key/1` captures a key matching
  `ssh-keyscan`, a pinned connect runs a command, and a deliberately wrong pin
  is rejected. What is unit-tested here is the policy that must never regress —
  fail-closed without a pin, and comparison on the key blob alone.
  """
  use ExUnit.Case, async: true

  alias Orbit.Securepoint.SSH

  defp cfg(overrides \\ []) do
    struct!(
      %SSH.Config{
        host: "192.0.2.10",
        port: 22,
        user: "root",
        private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n"
      },
      overrides
    )
  end

  describe "fail-closed host-key policy" do
    test "refuses to connect when no host key is pinned" do
      assert {:error, msg} = SSH.connect(cfg())
      assert msg =~ "host key not pinned"
      assert msg =~ "refusing to connect unverified"
    end

    test "an empty or whitespace pin counts as no pin" do
      assert {:error, msg} = SSH.connect(cfg(host_key: ""))
      assert msg =~ "host key not pinned"

      assert {:error, msg} = SSH.connect(cfg(host_key: "   "))
      assert msg =~ "host key not pinned"
    end

    test "fetch_ipsec_status refuses just as hard — no silent spcgi-only path here" do
      assert {:error, msg} = SSH.fetch_ipsec_status(cfg(), true)
      assert msg =~ "host key not pinned"
    end

    test "only the explicit probe path may connect unpinned" do
      # Gets PAST the pin gate — it fails later, on this fixture's dummy key —
      # whereas every other entry point stops at the gate. That is the whole
      # distinction: probe_host_key/1 is the sole unpinned path (TOFU capture).
      assert {:error, msg} = SSH.probe_host_key(cfg())
      refute msg =~ "host key not pinned"
      assert msg =~ "bad SSH private key"
    end
  end

  describe "key_blob/1" do
    test "extracts the identity part, ignoring algorithm and comment" do
      assert SSH.key_blob("ssh-ed25519 AAAAC3NzaC1 orbit@dashboard") == "AAAAC3NzaC1"
      assert SSH.key_blob("  ssh-ed25519   AAAAC3NzaC1  ") == "AAAAC3NzaC1"
    end

    test "a bare blob passes through" do
      assert SSH.key_blob("AAAAC3NzaC1") == "AAAAC3NzaC1"
    end
  end

  describe "same_key?/2" do
    test "a differing comment is still the same key" do
      assert SSH.same_key?(
               "ssh-ed25519 AAAAC3NzaC1 box-was-renamed",
               "ssh-ed25519 AAAAC3NzaC1 captured-at-enrolment"
             )
    end

    test "a different blob is a different key" do
      refute SSH.same_key?("ssh-ed25519 AAAAC3NzaC1", "ssh-ed25519 BBBBC3NzaC1")
    end
  end

  describe "decode_private_key/1" do
    test "a missing key is named as such, not reported as a connect failure" do
      assert {:error, msg} = SSH.decode_private_key("")
      assert msg =~ "no SSH private key configured"

      assert {:error, _} = SSH.decode_private_key(nil)
    end

    test "an undecodable key is reported as a bad key" do
      assert {:error, msg} = SSH.decode_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n")
      assert msg =~ "bad SSH private key"
    end
  end
end
