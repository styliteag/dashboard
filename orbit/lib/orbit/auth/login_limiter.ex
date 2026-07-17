defmodule Orbit.Auth.LoginLimiter do
  @moduledoc """
  In-memory IP-based brute-force limiter — mirror of the backend's
  LoginLimiter (auth/security.py, US-1.4): 5 failures within 15 minutes lock
  the IP for 15 minutes; a successful login clears the state.

  A GenServer holding a plain map. The Python original is a process-local
  singleton with the explicit "one worker only" constraint — on the BEAM the
  single GenServer gives the same serialized semantics without that
  deployment rule.

  `now` is injectable (monotonic milliseconds) for deterministic tests.
  """

  use GenServer

  @max_failed 5
  @window_ms 15 * 60 * 1000
  @lock_ms 15 * 60 * 1000

  def start_link(opts) do
    # name: nil = anonymous instance (tests); default = app-wide singleton.
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, :ok)
      name -> GenServer.start_link(__MODULE__, :ok, name: name)
    end
  end

  @spec locked?(GenServer.server(), String.t(), integer() | nil) :: boolean()
  def locked?(server \\ __MODULE__, ip, now \\ nil) do
    GenServer.call(server, {:locked?, ip, now || mono_ms()})
  end

  @doc "Record a failed login. Returns true iff this triggered a NEW lock."
  @spec record_failure(GenServer.server(), String.t(), integer() | nil) :: boolean()
  def record_failure(server \\ __MODULE__, ip, now \\ nil) do
    GenServer.call(server, {:record_failure, ip, now || mono_ms()})
  end

  @spec record_success(GenServer.server(), String.t()) :: :ok
  def record_success(server \\ __MODULE__, ip) do
    GenServer.call(server, {:record_success, ip})
  end

  @impl true
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_call({:locked?, ip, now}, _from, state) do
    locked =
      case state[ip] do
        %{locked_until: until} -> until > now
        nil -> false
      end

    {:reply, locked, state}
  end

  def handle_call({:record_failure, ip, now}, _from, state) do
    entry = Map.get(state, ip, %{failures: [], locked_until: 0})
    failures = [now | Enum.filter(entry.failures, &(now - &1 < @window_ms))]

    {triggered, entry} =
      if length(failures) >= @max_failed and entry.locked_until <= now do
        {true, %{failures: failures, locked_until: now + @lock_ms}}
      else
        {false, %{entry | failures: failures}}
      end

    {:reply, triggered, Map.put(state, ip, entry)}
  end

  def handle_call({:record_success, ip}, _from, state) do
    {:reply, :ok, Map.delete(state, ip)}
  end

  defp mono_ms, do: System.monotonic_time(:millisecond)
end
