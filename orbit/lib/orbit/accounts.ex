defmodule Orbit.Accounts do
  @moduledoc """
  Account lookup + login flow, mirroring backend/src/app/auth/routes.py.

  The password step NEVER mints a session on its own: it returns a challenge
  (`:verify` / `:enroll`) and the web layer keeps pending-MFA state until
  `verify_totp/3` (or a passkey, later) passes. Only exception: the bootstrap
  seed admin is password-only (`:done`).

  Pure decision logic lives in `login_step/2` (DB-free, fully testable);
  `login/3` is the thin DB + limiter wrapper. Audit writes stay with the
  callers (the web layer owns commit ordering, mirroring "routes own
  commit").
  """

  import Ecto.Query

  alias Orbit.Accounts.User
  alias Orbit.Auth.{LoginLimiter, Password, TOTP}
  alias Orbit.Repo

  @type challenge ::
          {:done, User.t()}
          | {:verify, User.t(), %{totp: boolean(), webauthn: boolean()}}
          | {:enroll, User.t()}
  @type login_error :: :rate_limited | :invalid_credentials | :account_disabled

  @spec get_user_by_username(String.t()) :: User.t() | nil
  def get_user_by_username(username) when is_binary(username) do
    Repo.one(from(u in User, where: u.username == ^username, preload: :groups))
  end

  @spec get_user(integer()) :: User.t() | nil
  def get_user(id), do: Repo.one(from(u in User, where: u.id == ^id, preload: :groups))

  @doc "A non-revoked `orbit_` api key by its raw token (sha256 lookup), or nil."
  @spec get_api_key_by_token(String.t()) :: Orbit.Accounts.ApiKey.t() | nil
  def get_api_key_by_token(token) when is_binary(token) do
    hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

    Repo.one(
      from(k in Orbit.Accounts.ApiKey,
        where: k.key_hash == ^hash and is_nil(k.revoked_at),
        preload: :groups
      )
    )
  end

  @doc """
  Step 1 of login: password + account state, rate-limited per IP.

  Returns `{:ok, challenge}` or `{:error, reason}`; on `:invalid_credentials`
  the limiter has already recorded the failure (the web layer audits
  `lock_triggered` separately via the limiter return if needed).
  """
  @spec login(String.t(), String.t(), String.t()) ::
          {:ok, challenge()} | {:error, login_error()}
  def login(username, password, ip) do
    if LoginLimiter.locked?(ip) do
      {:error, :rate_limited}
    else
      user = get_user_by_username(username)

      case login_step(user, password) do
        {:error, :invalid_credentials} = err ->
          LoginLimiter.record_failure(ip)
          err

        {:ok, _} = ok ->
          # Success clears failure state only when a session is actually
          # minted (complete_login in python does that) — the web layer
          # calls LoginLimiter.record_success/1 there.
          ok

        other ->
          other
      end
    end
  end

  @doc """
  Pure password-step decision — `user` may be nil (unknown username): a dummy
  Argon2 verify still runs so latency cannot enumerate usernames.

  `factors_fn` resolves the second-factor state only AFTER the password
  passed (lazy: no DB touch on the failure paths); tests inject their own.
  """
  @spec login_step(User.t() | nil, String.t(), (User.t() ->
                                                  %{
                                                    totp: boolean(),
                                                    webauthn: boolean()
                                                  })) ::
          {:ok, challenge()} | {:error, login_error()}
  def login_step(user, password, factors_fn \\ &factor_state/1) do
    cond do
      not Password.verify_constant_time(password, user && user.password_hash) ->
        {:error, :invalid_credentials}

      user.disabled ->
        {:error, :account_disabled}

      # The bootstrap seed admin is password-only (no 2FA) — session now.
      user.is_bootstrap ->
        {:ok, {:done, user}}

      true ->
        factors = factors_fn.(user)

        if factors.totp or factors.webauthn do
          {:ok, {:verify, user, factors}}
        else
          {:ok, {:enroll, user}}
        end
    end
  end

  @doc "(totp_enrolled, has_passkey) for the given user — mirror of user_factor_state."
  @spec factor_state(User.t()) :: %{totp: boolean(), webauthn: boolean()}
  def factor_state(%User{} = user) do
    %{totp: totp_enrolled?(user), webauthn: passkey_count(user) > 0}
  end

  @doc """
  Step 2: TOTP against the fernet-encrypted enrolled secret. Returns false
  for users without an enrolled factor — never a bypass.
  """
  @spec verify_totp(User.t(), String.t(), keyword()) :: boolean()
  def verify_totp(user, code, opts \\ [])

  def verify_totp(%User{totp_enabled: true, totp_secret_enc: enc}, code, opts)
      when is_binary(enc) do
    case Orbit.Crypto.decrypt(enc) do
      {:ok, secret} -> TOTP.verify(secret, code, opts)
      {:error, _} -> false
    end
  end

  def verify_totp(%User{}, _code, _opts), do: false

  @spec totp_enrolled?(User.t()) :: boolean()
  def totp_enrolled?(%User{totp_enabled: enabled, totp_secret_enc: enc}) do
    enabled == true and is_binary(enc)
  end

  defp passkey_count(%User{id: id}) do
    Repo.one(from(c in "webauthn_credentials", where: c.user_id == ^id, select: count()))
  end
end
