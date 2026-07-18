defmodule Orbit.Auth.WebauthnTest do
  @moduledoc """
  DB-free tests for the passkey ceremony helpers (webauthn_svc.py parity).

  A physical/virtual authenticator can't be driven in the suite, so the crypto
  path is proven against a hand-crafted `none`-attestation registration vector:
  we build the exact bytes a browser would return for a known challenge and
  assert `Wax.register` accepts them and that we slice out the *byte-identical*
  raw COSE public key (the round-trip the deferred login slice depends on).
  """

  use ExUnit.Case, async: true

  alias Orbit.Auth.Webauthn

  # A fixed COSE EC-P256 public key. "none" attestation does not validate the
  # key is on-curve, so any 32-byte x/y serve as a deterministic vector.
  @cose_x :binary.copy(<<0x11>>, 32)
  @cose_y :binary.copy(<<0x22>>, 32)
  @cred_id :binary.copy(<<0xAB>>, 16)

  # The decoded COSE map (kty EC2, alg ES256, crv P-256, x, y) as Wax.Utils.CBOR
  # yields it back (byte tags unwrapped).
  @cose_decoded %{1 => 2, 3 => -7, -1 => 1, -2 => @cose_x, -3 => @cose_y}

  defp cose_bytes do
    CBOR.encode(%{
      1 => 2,
      3 => -7,
      -1 => 1,
      -2 => %CBOR.Tag{tag: :bytes, value: @cose_x},
      -3 => %CBOR.Tag{tag: :bytes, value: @cose_y}
    })
  end

  # Build the credential map a browser would POST for this challenge.
  defp registration_vector(challenge) do
    origin = challenge.origin |> List.wrap() |> List.first()
    cose = cose_bytes()

    # flags: UP(0x01) | UV(0x04) | AT(0x40)
    auth_data =
      :crypto.hash(:sha256, challenge.rp_id) <>
        <<0x45>> <>
        <<0::32>> <>
        <<0::128>> <>
        <<byte_size(@cred_id)::unsigned-big-integer-size(16)>> <>
        @cred_id <>
        cose

    att_obj =
      CBOR.encode(%{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => %CBOR.Tag{tag: :bytes, value: auth_data}
      })

    client_data =
      Jason.encode!(%{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge.bytes, padding: false),
        "origin" => origin
      })

    %{
      "id" => Base.url_encode64(@cred_id, padding: false),
      "rawId" => Base.url_encode64(@cred_id, padding: false),
      "type" => "public-key",
      "response" => %{
        "attestationObject" => Base.url_encode64(att_obj, padding: false),
        "clientDataJSON" => Base.url_encode64(client_data, padding: false),
        "transports" => ["internal", "hybrid"]
      }
    }
  end

  describe "registration_options/3" do
    test "emits a base64url options map + a stashable challenge struct" do
      {options, challenge} = Webauthn.registration_options(42, "alice", [])

      assert %Wax.Challenge{type: :attestation} = challenge
      assert options["rp"]["id"] == challenge.rp_id
      assert options["user"]["name"] == "alice"
      # user.id is the decimal id, base64url-encoded (str(user_id).encode()).
      assert options["user"]["id"] == Base.url_encode64("42", padding: false)
      # challenge field mirrors the struct bytes.
      assert options["challenge"] == Base.url_encode64(challenge.bytes, padding: false)
      assert %{"type" => "public-key", "alg" => -7} in options["pubKeyCredParams"]
      assert options["excludeCredentials"] == []
      assert options["attestation"] == "none"
    end

    test "excludeCredentials carries existing credentials with transports" do
      existing = [%{credential_id: "abc123", transports: "internal,hybrid"}]
      {options, _challenge} = Webauthn.registration_options(1, "bob", existing)

      assert [%{"type" => "public-key", "id" => "abc123", "transports" => ["internal", "hybrid"]}] =
               options["excludeCredentials"]
    end
  end

  describe "verify_registration/2" do
    test "accepts a valid none-attestation vector and slices raw COSE bytes" do
      {_options, challenge} = Webauthn.registration_options(7, "carol", [])
      credential = registration_vector(challenge)

      assert {:ok, verified} = Webauthn.verify_registration(credential, challenge)
      assert verified.credential_id == Base.url_encode64(@cred_id, padding: false)
      assert verified.sign_count == 0
      assert verified.transports == ["internal", "hybrid"]

      # Byte-identical raw COSE — the python stack reads the same column.
      assert verified.public_key == cose_bytes()
      # …and it round-trips back to the COSE map the login slice will need.
      assert {:ok, @cose_decoded, ""} = Wax.Utils.CBOR.decode(verified.public_key)
    end

    test "rejects a tampered challenge (origin/challenge mismatch is fatal)" do
      {_options, challenge} = Webauthn.registration_options(7, "carol", [])
      credential = registration_vector(challenge)

      # A fresh challenge → the client-data challenge bytes no longer match.
      {_options, other} = Webauthn.registration_options(7, "carol", [])
      assert {:error, _} = Webauthn.verify_registration(credential, other)
    end

    test "rejects a malformed credential map" do
      {_options, challenge} = Webauthn.registration_options(7, "carol", [])
      assert {:error, _} = Webauthn.verify_registration(%{"response" => %{}}, challenge)
      assert {:error, :invalid_credential} = Webauthn.verify_registration("nope", challenge)
    end
  end

  # A real P-256 keypair + a real ECDSA signature: unlike "none" registration,
  # Wax.authenticate verifies the assertion signature, so garbage keys won't do.
  @auth_cred_id :binary.copy(<<0xCD>>, 20)

  defp p256_keypair do
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, x::binary-size(32), y::binary-size(32)>> = pub

    cose =
      CBOR.encode(%{
        1 => 2,
        3 => -7,
        -1 => 1,
        -2 => %CBOR.Tag{tag: :bytes, value: x},
        -3 => %CBOR.Tag{tag: :bytes, value: y}
      })

    {priv, cose}
  end

  defp cred(cred_id, cose, transports \\ nil) do
    %{
      credential_id: Base.url_encode64(cred_id, padding: false),
      public_key: cose,
      transports: transports
    }
  end

  # Assertion authenticator data is just rpIdHash + flags + signCount (no
  # attested-credential-data, AT flag off); the signed message is
  # authData ‖ sha256(clientDataJSON), signed ES256 (DER, WebAuthn wire format).
  defp auth_vector(challenge, priv, cred_id, sign_count) do
    origin = challenge.origin |> List.wrap() |> List.first()
    auth_data = :crypto.hash(:sha256, challenge.rp_id) <> <<0x05>> <> <<sign_count::32>>

    client_data =
      Jason.encode!(%{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge.bytes, padding: false),
        "origin" => origin
      })

    msg = auth_data <> :crypto.hash(:sha256, client_data)
    sig = :crypto.sign(:ecdsa, :sha256, msg, [priv, :secp256r1])

    %{
      "id" => Base.url_encode64(cred_id, padding: false),
      "rawId" => Base.url_encode64(cred_id, padding: false),
      "type" => "public-key",
      "response" => %{
        "authenticatorData" => Base.url_encode64(auth_data, padding: false),
        "clientDataJSON" => Base.url_encode64(client_data, padding: false),
        "signature" => Base.url_encode64(sig, padding: false),
        "userHandle" => nil
      }
    }
  end

  describe "authentication_options/1" do
    test "emits allowCredentials + an authentication challenge" do
      creds = [cred(@auth_cred_id, <<>>, "internal,hybrid")]
      {options, challenge} = Webauthn.authentication_options(creds)

      assert %Wax.Challenge{type: :authentication} = challenge
      assert options["rpId"] == challenge.rp_id
      assert options["challenge"] == Base.url_encode64(challenge.bytes, padding: false)

      assert [%{"type" => "public-key", "transports" => ["internal", "hybrid"]}] =
               options["allowCredentials"]
    end
  end

  describe "verify_authentication/3" do
    test "accepts an assertion signed by the stored key and returns the new counter" do
      {priv, cose} = p256_keypair()
      creds = [cred(@auth_cred_id, cose, "internal")]
      {_options, challenge} = Webauthn.authentication_options(creds)
      assertion = auth_vector(challenge, priv, @auth_cred_id, 9)

      assert {:ok, verified} = Webauthn.verify_authentication(assertion, challenge, creds)
      assert verified.credential_id == Base.url_encode64(@auth_cred_id, padding: false)
      assert verified.sign_count == 9
    end

    test "rejects an assertion for a credential the user does not have (cross-user guard)" do
      {priv, cose} = p256_keypair()
      creds = [cred(@auth_cred_id, cose)]
      {_options, challenge} = Webauthn.authentication_options(creds)
      assertion = auth_vector(challenge, priv, @auth_cred_id, 1)

      # Empty creds = the pending user owns no matching key → no COSE to verify.
      assert {:error, _} = Webauthn.verify_authentication(assertion, challenge, [])
    end

    test "rejects a tampered signature" do
      {priv, cose} = p256_keypair()
      creds = [cred(@auth_cred_id, cose)]
      {_options, challenge} = Webauthn.authentication_options(creds)

      bad =
        challenge
        |> auth_vector(priv, @auth_cred_id, 1)
        |> put_in(["response", "signature"], Base.url_encode64(<<0::560>>, padding: false))

      assert {:error, _} = Webauthn.verify_authentication(bad, challenge, creds)
    end

    test "rejects a stale challenge (fresh challenge → clientdata mismatch)" do
      {priv, cose} = p256_keypair()
      creds = [cred(@auth_cred_id, cose)]
      {_options, challenge} = Webauthn.authentication_options(creds)
      assertion = auth_vector(challenge, priv, @auth_cred_id, 1)
      {_options, other} = Webauthn.authentication_options(creds)

      assert {:error, _} = Webauthn.verify_authentication(assertion, other, creds)
    end
  end
end
