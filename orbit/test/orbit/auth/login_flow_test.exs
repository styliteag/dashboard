defmodule Orbit.Auth.LoginFlowTest do
  @moduledoc """
  The login state machine, table-driven: every (state, event) pair is either
  an explicit transition below or refused. Regression guard for the MFA
  enroll bypass — a pending_verify session must never reach the enroll
  events.
  """

  use ExUnit.Case, async: true

  alias Orbit.Auth.LoginFlow

  @allowed [
    # A password step from any state restarts the flow (fresh session).
    {:anonymous, {:password, :done}, :full},
    {:anonymous, {:password, :verify}, :pending_verify},
    {:anonymous, {:password, :enroll}, :pending_enroll},
    {:pending_verify, {:password, :enroll}, :pending_enroll},
    {:pending_enroll, {:password, :verify}, :pending_verify},
    {:full, {:password, :verify}, :pending_verify},
    # Second factor: only the step the password outcome chose.
    {:pending_verify, :show_challenge, :pending_verify},
    {:pending_verify, :factor_verified, :full},
    {:pending_enroll, :begin_enroll, :pending_enroll},
    {:pending_enroll, :factor_enrolled, :full},
    # Logout from anywhere.
    {:anonymous, :logout, :anonymous},
    {:pending_verify, :logout, :anonymous},
    {:pending_enroll, :logout, :anonymous},
    {:full, :logout, :anonymous}
  ]

  @refused [
    # The bypass: password-only (verify kind) must not enroll a new factor.
    {:pending_verify, :begin_enroll},
    {:pending_verify, :factor_enrolled},
    # Nor may an enrolling session claim a verified factor it does not have.
    {:pending_enroll, :show_challenge},
    {:pending_enroll, :factor_verified},
    # Nothing but a password step leaves anonymous.
    {:anonymous, :show_challenge},
    {:anonymous, :factor_verified},
    {:anonymous, :begin_enroll},
    {:anonymous, :factor_enrolled},
    # A full session has no pending second-factor step.
    {:full, :show_challenge},
    {:full, :factor_verified},
    {:full, :begin_enroll},
    {:full, :factor_enrolled},
    # Unknown input fails closed.
    {:pending_verify, :bogus},
    {:pending_enroll, {:password, :bogus}}
  ]

  describe "transition/2" do
    for {from, event, to} <- @allowed do
      test "#{inspect(from)} --#{inspect(event)}--> #{inspect(to)}" do
        assert LoginFlow.transition(unquote(from), unquote(Macro.escape(event))) ==
                 {:ok, unquote(to)}

        assert LoginFlow.allowed?(unquote(from), unquote(Macro.escape(event)))
      end
    end

    for {from, event} <- @refused do
      test "#{inspect(from)} refuses #{inspect(event)}" do
        assert LoginFlow.transition(unquote(from), unquote(Macro.escape(event))) ==
                 {:error, :invalid_transition}

        refute LoginFlow.allowed?(unquote(from), unquote(Macro.escape(event)))
      end
    end

    test "every second-factor event is reachable from exactly one pending state" do
      for event <- [:show_challenge, :factor_verified, :begin_enroll, :factor_enrolled] do
        sources = Enum.filter(LoginFlow.states(), &LoginFlow.allowed?(&1, event))
        assert length(sources) == 1, "#{inspect(event)} allowed from #{inspect(sources)}"
      end
    end
  end

  describe "session encoding" do
    test "only the two pending states round-trip through the session" do
      for state <- [:pending_verify, :pending_enroll] do
        assert state |> LoginFlow.to_session() |> LoginFlow.from_session() == state
      end
    end

    test "missing or foreign session values decode to anonymous (fail closed)" do
      for raw <- [nil, "", "full", "pending_enroll ", :pending_enroll, 1] do
        assert LoginFlow.from_session(raw) == :anonymous
      end
    end
  end
end
