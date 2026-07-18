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

  alias Orbit.Accounts.{Group, User, WebauthnCredential}
  alias Orbit.Auth.{LoginLimiter, Password, TOTP}
  alias Orbit.Instances.Instance
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

  @doc "All users alphabetical, groups preloaded — the superadmin rights read."
  @spec list_users() :: [User.t()]
  def list_users do
    Repo.all(from(u in User, order_by: u.username, preload: :groups))
  end

  @doc """
  Rights-management group overview: every group alphabetical with its member
  count and (non-deleted) instance count. Counts run as two grouped queries
  and merge in — no per-group N+1.
  """
  @spec list_groups() :: [
          %{
            id: integer(),
            name: String.t(),
            user_count: non_neg_integer(),
            instance_count: non_neg_integer()
          }
        ]
  def list_groups do
    user_counts =
      from(ug in "user_groups", group_by: ug.group_id, select: {ug.group_id, count(ug.user_id)})
      |> Repo.all()
      |> Map.new()

    instance_counts =
      from(i in Instance,
        where: is_nil(i.deleted_at),
        group_by: i.group_id,
        select: {i.group_id, count(i.id)}
      )
      |> Repo.all()
      |> Map.new()

    from(g in Group, order_by: g.name, select: %{id: g.id, name: g.name})
    |> Repo.all()
    |> Enum.map(fn g ->
      Map.merge(g, %{
        user_count: Map.get(user_counts, g.id, 0),
        instance_count: Map.get(instance_counts, g.id, 0)
      })
    end)
  end

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
  Start TOTP enrollment (mfa_routes.setup_totp port): mint a fresh secret,
  store it fernet-encrypted with totp_enabled STILL false — it only becomes
  a factor after the first code confirms. Returns {secret, otpauth_uri}.
  """
  def begin_totp_enrollment(%User{} = user) do
    secret = Orbit.Auth.TOTP.generate_secret()

    {:ok, _} =
      user
      |> Ecto.Changeset.change(%{
        totp_secret_enc: Orbit.Crypto.encrypt(secret),
        totp_enabled: false
      })
      |> Repo.update()

    issuer = Application.get_env(:orbit, :mfa_issuer, "Orbit Dashboard")
    {secret, Orbit.Auth.TOTP.provisioning_uri(secret, user.username, issuer)}
  end

  @doc """
  Finish enrollment (mfa_routes.confirm_totp port): verify the first code
  against the pending secret, flip totp_enabled. Returns the updated user
  or an error (no enrollment in progress / invalid code).
  """
  def confirm_totp_enrollment(%User{totp_secret_enc: nil}, _code),
    do: {:error, :no_enrollment}

  def confirm_totp_enrollment(%User{} = user, code) do
    secret = Orbit.Crypto.decrypt!(user.totp_secret_enc)

    if Orbit.Auth.TOTP.verify(secret, code) do
      user |> Ecto.Changeset.change(%{totp_enabled: true}) |> Repo.update()
    else
      {:error, :invalid_code}
    end
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

  # -- Passkey (WebAuthn) self-service management (mfa_routes.py port) --------

  @doc "The user's passkeys, oldest first (stable list order for the UI)."
  @spec list_credentials(User.t()) :: [WebauthnCredential.t()]
  def list_credentials(%User{id: id}) do
    Repo.all(from(c in WebauthnCredential, where: c.user_id == ^id, order_by: [asc: c.id]))
  end

  @doc "MfaMethods payload: raw totp_enabled flag + the passkey list."
  @spec mfa_methods(User.t()) :: %{totp_enabled: boolean(), passkeys: [WebauthnCredential.t()]}
  def mfa_methods(%User{} = user) do
    %{totp_enabled: user.totp_enabled == true, passkeys: list_credentials(user)}
  end

  @doc """
  Persist a verified passkey (output of `Orbit.Auth.Webauthn.verify_registration/2`).
  `created_at` is set explicitly — the column is Alembic-owned with a server
  default, but we set it so the returned struct is complete without a re-read.
  """
  @spec add_credential(User.t(), map(), String.t() | nil) ::
          {:ok, WebauthnCredential.t()} | {:error, Ecto.Changeset.t()}
  def add_credential(%User{id: id}, verified, name) do
    %WebauthnCredential{}
    |> Ecto.Changeset.change(%{
      user_id: id,
      credential_id: verified.credential_id,
      public_key: verified.public_key,
      sign_count: verified.sign_count,
      name: normalize_name(name),
      transports: normalize_transports(verified.transports),
      created_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
    # The unique index is the alembic-created `credential_id`, not Ecto's
    # default name — without this the duplicate-insert path raises instead of
    # returning a changeset error (excludeCredentials usually prevents dupes).
    |> Ecto.Changeset.unique_constraint(:credential_id, name: "credential_id")
    |> Repo.insert()
  end

  @doc """
  Remove a passkey — never the account's last remaining second factor.

  Mirrors `delete_passkey`: a user's own credential only; blocked when it is the
  last factor (`not totp_enabled and count <= 1`, count INCLUDING the target).
  Returns the deleted credential (for the audit target) or an error.
  """
  @spec delete_credential(User.t(), integer()) ::
          {:ok, WebauthnCredential.t()} | {:error, :not_found | :last_factor}
  def delete_credential(%User{} = user, cred_id) do
    cred = Repo.get(WebauthnCredential, cred_id)

    cond do
      is_nil(cred) or cred.user_id != user.id ->
        {:error, :not_found}

      last_factor?(user.totp_enabled == true, length(list_credentials(user))) ->
        {:error, :last_factor}

      true ->
        {:ok, _} = Repo.delete(cred)
        {:ok, cred}
    end
  end

  @doc """
  Pure last-factor guard (mfa_routes delete_passkey): with no TOTP and one (or
  fewer) passkeys, that passkey is the only 2FA and must not be removed.
  `count` INCLUDES the credential being removed.
  """
  @spec last_factor?(boolean(), non_neg_integer()) :: boolean()
  def last_factor?(totp_enabled?, count), do: not totp_enabled? and count <= 1

  defp normalize_name(name) when is_binary(name) do
    case String.trim(name) do
      "" -> nil
      trimmed -> String.slice(trimmed, 0, 128)
    end
  end

  defp normalize_name(_), do: nil

  defp normalize_transports(list) when is_list(list) do
    case list |> Enum.filter(&is_binary/1) |> Enum.join(",") |> String.slice(0, 255) do
      "" -> nil
      joined -> joined
    end
  end

  defp normalize_transports(_), do: nil
end
