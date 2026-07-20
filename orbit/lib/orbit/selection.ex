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

  @rank_reason %{
    @rank_instance_specific => "instance",
    @rank_instance_category => "instance_category",
    @rank_global_specific => "global",
    @rank_global_category => "global_category"
  }

  @doc """
  Pure resolve over a rule list: `{on, by}` for one (consumer, instance,
  check) — python model.resolve parity. `by` names the deciding level
  (instance / instance_category / global / global_category) or "default"
  (base default off). Rules are {consumer, instance_id | nil, selector, mode}.
  """
  def resolve(consumer, check_key, instance_id, rules) do
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

    if best_rank == 0 do
      {false, "default"}
    else
      {best_mode == "include", @rank_reason[best_rank]}
    end
  end

  @doc "Boolean resolve (see resolve/4)."
  def is_on(consumer, check_key, instance_id, rules) do
    resolve(consumer, check_key, instance_id, rules) |> elem(0)
  end

  @doc "Cached resolve for the dispatch path (default OFF until first load)."
  def is_on_live(consumer, check_key, instance_id) do
    is_on(consumer, check_key, instance_id, :persistent_term.get(@rules_key, []))
  end

  @doc "Synchronous re-load (tests / after writes)."
  def reload(server \\ __MODULE__), do: GenServer.call(server, :reload)

  # -- write side (selection/store.py + model.py validation port) ------------

  @check_categories ~w(agent agent.collect maintenance ping http memory cpu load swap disk gateway
    pf_states ntp ipsec.service ipsec.tunnel ipsec.tunnel_ping connectivity service
    cert iface_errors firmware)
  @availability "availability"
  @channels ~w(mattermost telegram email)
  @consumers ["checkmk" | @channels]

  def consumers, do: @consumers

  @doc "Selectable categories: checkmk never gets availability (host up/down is checkmk's own)."
  def categories_for("checkmk"), do: @check_categories
  def categories_for(_channel), do: [@availability | @check_categories]

  def valid_consumer?(consumer), do: consumer in @consumers
  def valid_mode?(mode), do: mode in ["include", "exclude"]

  @doc "Category token or full check key whose category prefix is known."
  def valid_selector?(consumer, selector) do
    category(selector) in categories_for(consumer)
  end

  @doc "Upsert one rule (identity: consumer+selector+instance, NULL-aware)."
  def set_rule(consumer, selector, mode, instance_id) do
    delete_rule(consumer, selector, instance_id)

    Orbit.Repo.query!(
      "INSERT INTO selection_rules (consumer, selector, mode, instance_id) VALUES (?, ?, ?, ?)",
      [consumer, selector, mode, instance_id]
    )

    reload_if_running()
    :ok
  end

  @doc "Remove one rule by identity (instance_id NULL needs IS NULL)."
  def delete_rule(consumer, selector, instance_id) do
    if instance_id == nil do
      Orbit.Repo.query!(
        "DELETE FROM selection_rules WHERE consumer = ? AND selector = ? AND instance_id IS NULL",
        [consumer, selector]
      )
    else
      Orbit.Repo.query!(
        "DELETE FROM selection_rules WHERE consumer = ? AND selector = ? AND instance_id = ?",
        [consumer, selector, instance_id]
      )
    end

    reload_if_running()
    :ok
  end

  @doc "One consumer's rules as resolve/4 tuples, fresh from the DB (tree UI)."
  def consumer_rules(consumer) do
    Orbit.Repo.query!(
      "SELECT consumer, instance_id, selector, mode FROM selection_rules WHERE consumer = ?",
      [consumer]
    ).rows
    |> Enum.map(fn [c, i, s, m] -> {c, i, s, m} end)
  end

  @doc "All rules with instance names for the editor."
  def list_rules do
    Orbit.Repo.query!(
      "SELECT r.id, r.consumer, r.selector, r.mode, r.instance_id, i.name " <>
        "FROM selection_rules r LEFT JOIN instances i ON i.id = r.instance_id " <>
        "ORDER BY r.consumer, r.selector"
    ).rows
    |> Enum.map(fn [id, consumer, selector, mode, iid, iname] ->
      %{
        id: id,
        consumer: consumer,
        selector: selector,
        mode: mode,
        instance_id: iid,
        instance_name: iname
      }
    end)
  end

  defp reload_if_running do
    if Process.whereis(__MODULE__), do: reload()
  catch
    :exit, _ -> :ok
  end

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
