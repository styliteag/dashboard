defmodule Orbit.GUI.SessionStash do
  @moduledoc """
  Short-lived, single-use stash of firewall WebUI session cookies keyed by
  the one-time handoff token — port of gui_session.py. The agent replays
  the firewall login and returns its session cookie; that cookie must reach
  the browser as a Set-Cookie on the proxy origin but must NEVER travel in
  the handoff URL (it would leak via access logs / Referer). So gui/open
  stashes it here keyed by the token, and gui/handoff pops it once.

  In-memory, single worker by design. Entries prune on access + expire with
  the token TTL.
  """

  use GenServer

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Stash cookies (list of {name, value}) for a token; no-op when empty."
  def put(server \\ __MODULE__, token, cookies, ttl_seconds) do
    GenServer.cast(server, {:put, token, cookies, ttl_seconds})
  catch
    :exit, _ -> :ok
  end

  @doc "Pop + remove the cookies for a token ([] when missing/expired)."
  def pop(server \\ __MODULE__, token) do
    GenServer.call(server, {:pop, token})
  catch
    :exit, _ -> []
  end

  # -- pure transitions (unit-tested) ---------------------------------------

  @doc false
  def do_put(store, token, cookies, ttl_seconds, now_ms) do
    pairs = for {n, v} <- cookies, n not in [nil, ""], do: {n, v}
    store = prune(store, now_ms)
    if pairs == [], do: store, else: Map.put(store, token, {pairs, now_ms + ttl_seconds * 1000})
  end

  @doc false
  def do_pop(store, token, now_ms) do
    store = prune(store, now_ms)

    case Map.pop(store, token) do
      {{pairs, exp}, rest} when exp >= now_ms -> {pairs, rest}
      {_, rest} -> {[], rest}
    end
  end

  defp prune(store, now_ms) do
    store |> Enum.reject(fn {_, {_, exp}} -> exp < now_ms end) |> Map.new()
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_cast({:put, token, cookies, ttl}, store) do
    {:noreply, do_put(store, token, cookies, ttl, now_ms())}
  end

  @impl true
  def handle_call({:pop, token}, _from, store) do
    {pairs, rest} = do_pop(store, token, now_ms())
    {:reply, pairs, rest}
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
