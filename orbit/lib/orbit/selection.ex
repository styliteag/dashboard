defmodule Orbit.Selection do
  @moduledoc """
  Service-selection resolution — port of selection/model.py + the read side
  of selection/store.py, over the shared `selection_rules` table (python
  stays the writer until orbit grows the Views/Selection surface).

  A rule is {consumer, instance_id | nil, selector, mode}: selector is a
  category token (part before the first `:`) or a full check key; mode is
  include/exclude. Base default is OFF for every consumer — nothing sends
  until a rule includes it. Resolution is most-specific-wins: instance
  beats global, full key beats category (ranks 4/3/2/1).

  `is_on_live/3` reads a 60s-repolled :persistent_term cache (GeoIP.Store
  pattern) — the dispatch path never touches the DB.
  """

  use GenServer

  require Logger

  @rules_key {__MODULE__, :rules}
  @reload_ms 60_000

  @rank_instance_specific 4
  @rank_instance_category 3
  @rank_global_specific 2
  @rank_global_category 1

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Category token of a check key (part before the first colon)."
  def category(check_key), do: check_key |> String.split(":", parts: 2) |> hd()

  @doc """
  Pure resolve over a rule list: is `consumer` interested in `check_key`
  for `instance_id`? Rules are {consumer, instance_id | nil, selector, mode}.
  """
  def is_on(consumer, check_key, instance_id, rules) do
    cat = category(check_key)

    {best_rank, best_mode} =
      Enum.reduce(rules, {0, ""}, fn {r_consumer, r_instance, r_selector, r_mode}, acc ->
        {best, _} = acc
        is_instance = r_instance == instance_id

        rank =
          cond do
            r_consumer != consumer -> 0
            not (is_instance or is_nil(r_instance)) -> 0
            r_selector == check_key and is_instance -> @rank_instance_specific
            r_selector == check_key -> @rank_global_specific
            r_selector == cat and is_instance -> @rank_instance_category
            r_selector == cat -> @rank_global_category
            true -> 0
          end

        if rank > best, do: {rank, r_mode}, else: acc
      end)

    best_rank > 0 and best_mode == "include"
  end

  @doc "Cached resolve for the dispatch path (default OFF until first load)."
  def is_on_live(consumer, check_key, instance_id) do
    is_on(consumer, check_key, instance_id, :persistent_term.get(@rules_key, []))
  end

  @doc "Synchronous re-load (tests / after writes)."
  def reload(server \\ __MODULE__), do: GenServer.call(server, :reload)

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    load()
    Process.send_after(self(), :reload, @reload_ms)
    {:ok, %{}}
  end

  @impl true
  def handle_call(:reload, _from, state), do: {:reply, load(), state}

  @impl true
  def handle_info(:reload, state) do
    load()
    Process.send_after(self(), :reload, @reload_ms)
    {:noreply, state}
  end

  defp load do
    rules =
      Orbit.Repo.query!("SELECT consumer, instance_id, selector, mode FROM selection_rules").rows
      |> Enum.map(fn [c, i, s, m] -> {c, i, s, m} end)

    :persistent_term.put(@rules_key, rules)
    :ok
  rescue
    # Keep the previous snapshot — a DB hiccup must not flip routing.
    error ->
      Logger.warning("selection.load_failed error=#{Exception.message(error)}")
      :error
  end
end
