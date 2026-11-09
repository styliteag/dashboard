defmodule Orbit.Auth.LoginFlow do
  @moduledoc """
  The browser login flow as an explicit state machine. Pure: no conn, no DB.

      anonymous ──{:password, :done}────────────────────────────────▶ full
      anonymous ──{:password, :verify}─▶ pending_verify ──:factor_verified─▶ full
      anonymous ──{:password, :enroll}─▶ pending_enroll ──:factor_enrolled─▶ full

  - `{:password, outcome}` is allowed from every state: a new password step
    restarts the flow on a fresh session. `outcome` is what
    `Orbit.Accounts.login_step/3` decided (`:done` = bootstrap admin only).
  - `:show_challenge` (TOTP page, passkey options) is a self-loop of
    pending_verify; `:begin_enroll` (mint the pending secret) is a self-loop
    of pending_enroll. Each second-factor event belongs to exactly ONE
    pending state.
  - `:logout` returns to anonymous from anywhere.

  The pending state is stored in the session (`to_session/1`) next to
  `mfa_user_id`; OrbitWeb.UserAuth.pending_mfa_user/2 asks `allowed?/2` for
  the controller action's event before handing out the user.

  Regression (MFA enroll bypass): the pending session did not record its
  kind, so a password-only session of a user WITH a factor reached the
  enroll actions, overwrote the real TOTP secret with a self-minted one and
  logged in — the password alone beat the second factor and destroyed it.
  """

  @type state :: :anonymous | :pending_verify | :pending_enroll | :full
  @type event ::
          {:password, :done | :verify | :enroll}
          | :show_challenge
          | :factor_verified
          | :begin_enroll
          | :factor_enrolled
          | :logout

  @states [:anonymous, :pending_verify, :pending_enroll, :full]

  @password_outcomes %{done: :full, verify: :pending_verify, enroll: :pending_enroll}

  @second_factor %{
    {:pending_verify, :show_challenge} => :pending_verify,
    {:pending_verify, :factor_verified} => :full,
    {:pending_enroll, :begin_enroll} => :pending_enroll,
    {:pending_enroll, :factor_enrolled} => :full
  }

  @session_values %{"pending_verify" => :pending_verify, "pending_enroll" => :pending_enroll}

  @spec states() :: [state()]
  def states, do: @states

  @doc "Next state for `event` in `state`, or `{:error, :invalid_transition}`."
  @spec transition(state(), event() | term()) :: {:ok, state()} | {:error, :invalid_transition}
  def transition(state, event) when state in @states, do: next(state, event)
  def transition(_state, _event), do: {:error, :invalid_transition}

  @spec allowed?(state(), event() | term()) :: boolean()
  def allowed?(state, event), do: match?({:ok, _}, transition(state, event))

  @doc "Session encoding of a pending state (the only states ever stored)."
  @spec to_session(:pending_verify | :pending_enroll) :: String.t()
  def to_session(:pending_verify), do: "pending_verify"
  def to_session(:pending_enroll), do: "pending_enroll"

  @doc "Decode a session value; anything unknown or absent is `:anonymous`."
  @spec from_session(term()) :: state()
  def from_session(value) when is_binary(value), do: Map.get(@session_values, value, :anonymous)
  def from_session(_value), do: :anonymous

  defp next(_state, {:password, outcome}) do
    case Map.fetch(@password_outcomes, outcome) do
      {:ok, state} -> {:ok, state}
      :error -> {:error, :invalid_transition}
    end
  end

  defp next(_state, :logout), do: {:ok, :anonymous}

  defp next(state, event) do
    case Map.fetch(@second_factor, {state, event}) do
      {:ok, to} -> {:ok, to}
      :error -> {:error, :invalid_transition}
    end
  end
end
