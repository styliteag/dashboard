defmodule Orbit.Alerts.Lifecycle do
  @moduledoc """
  Alert lifecycle (docs/alert-lifecycle.md): the reconciler that gives
  computed alerts an identity over time, plus ack/snooze.

  The computed surfaces stay the truth (DR-LC3): Checkmk/Prometheus/the
  checks tab never read this table. Only the Alerts page joins it, for
  "since when", "seen" and "quiet until".

  `plan/3` is pure — the whole state machine is testable without a DB;
  `reconcile/0` wraps it in the two queries and runs from the scheduler
  (single writer, so per-key uniqueness of unresolved rows is an
  invariant, not a constraint).
  """

  import Ecto.Query

  alias Orbit.Alerts.State
  alias Orbit.Repo

  require Logger

  @doc "Scheduler entry (30s tier). Returns :ok; failures are logged, never raised."
  def reconcile(now \\ DateTime.utc_now()) do
    computed =
      for {inst, checks} <- Orbit.Checks.Export.evaluated(nil, now),
          c <- checks,
          c.state != 0,
          do: {{inst.id, to_string(c.key)}, c.state}

    plan = plan(Map.new(computed), unresolved(), now)
    apply_plan(plan, now)
    :ok
  rescue
    e ->
      Logger.warning("alerts.reconcile.failed #{inspect(e)}")
      :ok
  catch
    # Pool checkout exits rather than raising; a stressed DB must not kill
    # the scheduler's job sequence.
    _kind, reason ->
      Logger.warning("alerts.reconcile.exit #{inspect(reason)}")
      :ok
  end

  @doc """
  The pure state machine: computed `%{{iid, key} => severity}` vs the
  unresolved rows.

  - unseen computed alert → `:insert` (first_seen = now)
  - still-present alert → `:touch` (last_seen + severity); a severity
    INCREASE past a live snooze also clears the snooze (DR-LC4 — a
    worsening alert must not stay quiet)
  - row whose alert vanished → `:resolve` (ack dies with it: the next
    occurrence is a new, un-acked incident)
  """
  def plan(computed, states, now) do
    by_key = Map.new(states, &{{&1.instance_id, &1.check_key}, &1})

    inserts =
      for {key, sev} <- computed, not Map.has_key?(by_key, key), do: {key, sev}

    touches =
      for {key, sev} <- computed, state = by_key[key], state != nil do
        unsnooze? =
          sev > state.severity and state.snoozed_until != nil and
            DateTime.compare(state.snoozed_until, now) == :gt

        {state, sev, unsnooze?}
      end

    resolves = for {key, state} <- by_key, not Map.has_key?(computed, key), do: state

    %{insert: inserts, touch: touches, resolve: resolves}
  end

  defp unresolved do
    from(s in State, where: is_nil(s.resolved_at)) |> Repo.all()
  end

  defp apply_plan(%{insert: inserts, touch: touches, resolve: resolves}, now) do
    for {{iid, key}, sev} <- inserts do
      Repo.insert!(%State{
        instance_id: iid,
        check_key: key,
        severity: sev,
        first_seen_at: now,
        last_seen_at: now
      })
    end

    for {state, sev, unsnooze?} <- touches do
      changes =
        [last_seen_at: now, severity: sev] ++ if(unsnooze?, do: [snoozed_until: nil], else: [])

      from(s in State, where: s.id == ^state.id) |> Repo.update_all(set: changes)
    end

    ids = Enum.map(resolves, & &1.id)

    if ids != [] do
      from(s in State, where: s.id in ^ids) |> Repo.update_all(set: [resolved_at: now])
    end
  end

  @doc "Unresolved lifecycle rows for the given instance ids, as %{{iid, key} => state} — the Alerts page's join."
  def states_for(instance_ids) do
    from(s in State,
      where: is_nil(s.resolved_at) and s.instance_id in ^instance_ids
    )
    |> Repo.all()
    |> Map.new(&{{&1.instance_id, &1.check_key}, &1})
  rescue
    # Throwaway test DB without the table: the page renders without
    # lifecycle decoration instead of crashing.
    _ -> %{}
  catch
    _kind, _reason -> %{}
  end

  @doc "Mark seen. Idempotent; only unresolved rows. Caller is write-gated and audits."
  def ack(instance_id, check_key, username, now \\ DateTime.utc_now()) do
    from(s in State,
      where:
        s.instance_id == ^instance_id and s.check_key == ^check_key and
          is_nil(s.resolved_at) and is_nil(s.acked_at)
    )
    |> Repo.update_all(set: [acked_by: username, acked_at: now])

    :ok
  end

  @doc "Quiet until `until`. Only unresolved rows. Caller is write-gated and audits."
  def snooze(instance_id, check_key, %DateTime{} = until) do
    from(s in State,
      where: s.instance_id == ^instance_id and s.check_key == ^check_key and is_nil(s.resolved_at)
    )
    |> Repo.update_all(set: [snoozed_until: until])

    :ok
  end

  @doc "Prune resolved rows past retention (batched via resolved_at index)."
  def prune do
    days = Orbit.Settings.effective("alert_history_retention_days")
    cutoff = DateTime.add(DateTime.utc_now(), -days * 86_400) |> DateTime.truncate(:second)
    naive = DateTime.to_naive(cutoff)

    %{num_rows: n} =
      Repo.query!(
        "DELETE FROM alert_states WHERE resolved_at IS NOT NULL AND resolved_at < ? " <>
          "ORDER BY resolved_at LIMIT 10000",
        [naive]
      )

    n
  rescue
    _ -> 0
  catch
    _kind, _reason -> 0
  end
end
