defmodule Orbit.Auth.Webauthn do
  @moduledoc """
  WebAuthn / passkey ceremony helpers — port of `auth/webauthn_svc.py`.

  The crypto lives in `wax_`; we own the challenge lifecycle (server-generated,
  single-use — the LiveView stashes it in socket state between the two calls)
  and the rp_id / accepted origins, the values that make WebAuthn fail with
  opaque browser errors when wrong.

  `registration_options/3` hand-builds the `PublicKeyCredentialCreationOptions`
  JSON the browser's `navigator.credentials.create` expects (base64url, no
  padding — the WebAuthn JSON wire format). `verify_registration/2` runs the
  attestation through `Wax.register/3` and extracts the fields to persist,
  keeping `public_key` as the **raw COSE bytes** sliced from the authenticator
  data so they are byte-identical to what the python stack stores.

  Only registration + its options are here (this slice is passkey MANAGEMENT).
  Authentication (passkey login) is a later slice with its own vector.
  """

  # COSE algorithm identifiers advertised to the authenticator (it picks one).
  # Matches py_webauthn's defaults: ES256, EdDSA, RS256.
  @es256 -7
  @eddsa -8
  @rs256 -257

  @doc """
  `{options_map, %Wax.Challenge{}}` for `navigator.credentials.create`.

  The options map is JSON-ready (base64url strings); the challenge struct is
  opaque server state to stash and hand back to `verify_registration/2`.
  `existing` are the user's current credentials (excluded so the same
  authenticator can't double-enroll).
  """
  @spec registration_options(integer(), String.t(), [map()]) :: {map(), Wax.Challenge.t()}
  def registration_options(user_id, username, existing) do
    challenge =
      Wax.new_registration_challenge(
        origin: origins(),
        rp_id: rp_id(),
        attestation: "none"
      )

    options = %{
      "rp" => %{"id" => rp_id(), "name" => rp_name()},
      "user" => %{
        # py_webauthn: str(user_id).encode() — the decimal id as bytes.
        "id" => b64(Integer.to_string(user_id)),
        "name" => username,
        "displayName" => username
      },
      "challenge" => b64(challenge.bytes),
      "pubKeyCredParams" => [
        %{"type" => "public-key", "alg" => @es256},
        %{"type" => "public-key", "alg" => @eddsa},
        %{"type" => "public-key", "alg" => @rs256}
      ],
      "timeout" => 60_000,
      "attestation" => "none",
      "excludeCredentials" => Enum.map(existing, &descriptor/1),
      "authenticatorSelection" => %{
        "residentKey" => "preferred",
        "requireResidentKey" => false,
        "userVerification" => "preferred"
      }
    }

    {options, challenge}
  end

  @doc """
  Verify a registration response (the `@simplewebauthn/browser`
  RegistrationResponseJSON map) against the stashed challenge.

  On success → `{:ok, %{credential_id, public_key, sign_count, transports}}`
  ready for `Orbit.Accounts.add_credential/3`. `public_key` is raw COSE bytes.
  """
  @spec verify_registration(map(), Wax.Challenge.t()) ::
          {:ok,
           %{
             credential_id: String.t(),
             public_key: binary(),
             sign_count: non_neg_integer(),
             transports: [String.t()]
           }}
          | {:error, term()}
  def verify_registration(credential, %Wax.Challenge{} = challenge) when is_map(credential) do
    with {:ok, response} <- fetch(credential, "response"),
         {:ok, att_b64} <- fetch(response, "attestationObject"),
         {:ok, cdj_b64} <- fetch(response, "clientDataJSON"),
         {:ok, attestation_object} <- b64d(att_b64),
         {:ok, client_data_json} <- b64d(cdj_b64),
         {:ok, {auth_data, _result}} <-
           Wax.register(attestation_object, client_data_json, challenge) do
      acd = auth_data.attested_credential_data

      {:ok,
       %{
         credential_id: b64(acd.credential_id),
         public_key: cose_key_bytes(auth_data),
         sign_count: auth_data.sign_count,
         transports: transports(response)
       }}
    else
      {:error, _} = err -> err
      other -> {:error, other}
    end
  end

  def verify_registration(_credential, _challenge), do: {:error, :invalid_credential}

  # -- COSE extraction ------------------------------------------------------

  # Slice the *raw* COSE public-key bytes out of the authenticator data instead
  # of re-encoding wax's decoded map (a re-encode is not guaranteed canonical
  # and could be rejected by another decoder). authData layout:
  #   rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) |
  #   credId(credIdLen) | COSEpublicKey | extensions?
  # The COSE key is everything after credId minus whatever CBOR.decode leaves as
  # trailing bytes (the extensions map, or nothing).
  defp cose_key_bytes(%{raw_bytes: raw, attested_credential_data: acd}) do
    cred_len = byte_size(acd.credential_id)

    <<_rp_hash::binary-size(32), _flags::8, _sign_count::32, _aaguid::binary-size(16),
      _len::unsigned-big-integer-size(16), _cred_id::binary-size(^cred_len), tail::binary>> = raw

    {:ok, _cose_map, ext_rest} = Wax.Utils.CBOR.decode(tail)
    binary_part(tail, 0, byte_size(tail) - byte_size(ext_rest))
  end

  # -- helpers --------------------------------------------------------------

  defp descriptor(%{credential_id: cid} = cred) do
    base = %{"type" => "public-key", "id" => cid}

    case parse_transports(cred[:transports] || cred["transports"]) do
      [] -> base
      ts -> Map.put(base, "transports", ts)
    end
  end

  # DB stores transports comma-joined; the JSON descriptor wants a list.
  defp parse_transports(nil), do: []
  defp parse_transports(""), do: []

  defp parse_transports(str) when is_binary(str),
    do:
      str |> String.split(",", trim: true) |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

  defp parse_transports(list) when is_list(list), do: list

  defp transports(response) do
    case response["transports"] do
      list when is_list(list) -> Enum.filter(list, &is_binary/1)
      _ -> []
    end
  end

  defp fetch(map, key) do
    case Map.get(map, key) do
      nil -> {:error, {:missing, key}}
      "" -> {:error, {:missing, key}}
      value -> {:ok, value}
    end
  end

  # WebAuthn JSON wire format is base64url WITHOUT padding.
  defp b64(bin), do: Base.url_encode64(bin, padding: false)

  defp b64d(str) do
    case Base.url_decode64(str, padding: false) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :bad_base64url}
    end
  end

  defp rp_id, do: Application.get_env(:orbit, :webauthn_rp_id, "localhost")
  defp rp_name, do: Application.get_env(:orbit, :webauthn_rp_name, "Orbit Dashboard")

  defp origins do
    case Application.get_env(:orbit, :webauthn_origins, ["http://localhost:8000"]) do
      [] -> ["http://localhost:8000"]
      list -> list
    end
  end
end
