defmodule Orbit.Enrollment do
  @moduledoc """
  Agent enrollment (§16): mint a one-time code for an instance, redeem it for
  that instance's agent token. Mirror of agent_hub/routes/enroll.py.

  `code_hash` is the code's SHA-256 (the code itself is high-entropy random,
  a fast hash is fine); only the hash is stored. Redemption is atomic (code
  consumed + token minted + transport flipped in one transaction) so a
  concurrent double-redeem can't mint twice.
  """

  import Ecto.Query

  alias Orbit.Enrollment.EnrollmentCode
  alias Orbit.Instances.Instance
  alias Orbit.Repo

  @code_ttl_seconds 3600

  @doc "Mint a one-time, 1-hour code for an instance. Returns {code, expires_at}."
  @spec create_code(integer()) :: {String.t(), DateTime.t()}
  def create_code(instance_id) do
    code = random_token(24)
    expires_at = DateTime.utc_now() |> DateTime.add(@code_ttl_seconds, :second) |> trunc_s()

    Repo.insert_all("enrollment_codes", [
      [
        code_hash: hash_code(code),
        instance_id: instance_id,
        expires_at: DateTime.to_naive(expires_at),
        created_at: DateTime.to_naive(trunc_s(DateTime.utc_now()))
      ]
    ])

    {code, expires_at}
  end

  @doc """
  Exchange a valid, unused, unexpired code for the instance's agent token.
  Consumes the code and flips the instance to push transport (minting a token
  if absent). Returns {:ok, token, instance_id} or {:error, reason}.
  """
  @spec redeem(String.t()) ::
          {:ok, String.t(), integer()} | {:error, :invalid | :instance_gone}
  def redeem(code) do
    Repo.transaction(fn ->
      now = DateTime.utc_now()

      row =
        Repo.one(
          from(c in EnrollmentCode,
            where: c.code_hash == ^hash_code(code),
            lock: "FOR UPDATE"
          )
        )

      with %EnrollmentCode{used_at: nil} = row <- row,
           false <- expired?(row, now),
           %Instance{deleted_at: nil} = inst <- Repo.get(Instance, row.instance_id) do
        token = inst.agent_token || random_token(48)
        naive_now = DateTime.to_naive(trunc_s(now))

        Repo.update_all(from(i in Instance, where: i.id == ^inst.id),
          set: [agent_token: token, transport: "push", updated_at: naive_now]
        )

        Repo.update_all(from(c in EnrollmentCode, where: c.id == ^row.id),
          set: [used_at: naive_now]
        )

        {token, inst.id}
      else
        %Instance{} -> Repo.rollback(:instance_gone)
        nil -> Repo.rollback(:invalid)
        _ -> Repo.rollback(:invalid)
      end
    end)
    |> case do
      {:ok, {token, instance_id}} -> {:ok, token, instance_id}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec hash_code(String.t()) :: String.t()
  def hash_code(code), do: :crypto.hash(:sha256, code) |> Base.encode16(case: :lower)

  defp expired?(%EnrollmentCode{expires_at: exp}, now), do: DateTime.compare(exp, now) == :lt

  # secrets.token_urlsafe(n) parity: n random bytes, urlsafe base64, no padding.
  defp random_token(bytes),
    do: Base.url_encode64(:crypto.strong_rand_bytes(bytes), padding: false)

  defp trunc_s(dt), do: DateTime.truncate(dt, :second)
end
