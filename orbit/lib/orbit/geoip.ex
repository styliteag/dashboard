defmodule Orbit.GeoIP do
  @moduledoc """
  GeoIP access restriction (docs/geoip-access-restriction.md) — facade over
  the pure rules, the mmdb lookup, the config store and the DynDNS resolver.
  `evaluate/1` is the one yes/no every enforcement point (HTTP plug,
  LiveView socket hook) uses, so their notion of "blocked" can never drift.

  The CrowdSec blocklist (DR-G8) has its own switch and applies even when
  the country restriction is off — only both-off short-circuits.
  """

  alias Orbit.GeoIP.Crowdsec
  alias Orbit.GeoIP.Dyndns
  alias Orbit.GeoIP.Lookup
  alias Orbit.GeoIP.Rules
  alias Orbit.GeoIP.Store

  @type verdict :: {:allow | :deny, reason :: String.t(), country :: String.t() | nil}

  @spec evaluate(String.t()) :: verdict()
  def evaluate(ip) do
    blocklist_on = Crowdsec.active?()

    cond do
      # Env-only kill switch (DR-G2): the rescue anchor when the config
      # itself locks everyone out; deliberately not a DB setting. Kills the
      # blocklist too (mirror of the python middleware).
      Application.get_env(:orbit, :geoip_disable, false) ->
        {:allow, "kill_switch", nil}

      not Rules.restricting?(Store.current_rules()) and not blocklist_on ->
        {:allow, "not_restricting", nil}

      true ->
        rules = Store.current_rules()
        db_ok = Lookup.db_available?()
        country = if db_ok, do: Lookup.country_for(ip)
        banned = if blocklist_on, do: &Crowdsec.is_banned/1
        decision = Rules.decide(ip, rules, country, Dyndns.resolved_ips(), db_ok, banned)
        {if(decision.allowed, do: :allow, else: :deny), decision.reason, decision.country}
    end
  end
end
