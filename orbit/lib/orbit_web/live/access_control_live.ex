defmodule OrbitWeb.AccessControlLive do
  @moduledoc """
  GeoIP access-restriction configuration (AccessControlPage/geoip routes
  port) — superadmin-only by design (DR-G6: deliberately NOT a generic
  settings key, this surface decides who can reach the dashboard at all).

  Countries as ISO-code list, whitelist entries validated through
  Rules.classify_entry (CIDR v4/v6 or DynDNS hostname). Lockout guard
  (DR-G5): when the NEW config would block the operator's own socket IP,
  the first save refuses with a warning — a second submit with the
  \"save anyway\" checkbox goes through (deliberate VPN switches happen).
  Saves audit geoip.config.update (allowlisted fields) and reload the
  gate cache immediately. Status row shows mmdb availability, CrowdSec
  sync health and the DynDNS-resolved bypass IPs.
  """

  use OrbitWeb, :live_view

  alias Orbit.Audit
  alias Orbit.GeoIP.Crowdsec
  alias Orbit.GeoIP.Dyndns
  alias Orbit.GeoIP.Lookup
  alias Orbit.GeoIP.Rules
  alias Orbit.GeoIP.Store

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket |> assign(error: nil, warning: nil) |> load()}
  end

  defp load(socket) do
    rules = Store.current_rules()

    assign(socket,
      enabled: rules.enabled,
      countries_text: rules.countries |> Enum.sort() |> Enum.join(", "),
      whitelist_text: whitelist_text(),
      db_available: Lookup.db_available?(),
      crowdsec: Crowdsec.status(),
      resolved: Dyndns.resolved_ips() |> Enum.sort(),
      blocks: blocks_by_reason(),
      refresh_busy: Map.get(socket.assigns, :refresh_busy, false),
      last_refresh: Orbit.GeoIP.Updater.last_download(),
      viewer_geo: viewer_geo(socket)
    )
  end

  # City+country the admin appears from (City edition; nil until the socket is
  # connected, or for a private/unknown IP). Display-only.
  defp viewer_geo(socket) do
    if Phoenix.LiveView.connected?(socket) do
      OrbitWeb.Geo.label(socket_ip(socket))
    end
  end

  # The raw whitelist entries come from the row (the parsed ruleset only
  # keeps them split into cidrs/hostnames).
  defp whitelist_text do
    case Orbit.Repo.query!("SELECT whitelist FROM geoip_config WHERE id = 1").rows do
      [[json]] ->
        case Jason.decode(json || "[]") do
          {:ok, list} -> Enum.join(list, "\n")
          _ -> ""
        end

      [] ->
        ""
    end
  rescue
    _ -> ""
  catch
    # A pool checkout exits rather than raising; same fallback, or a stressed
    # database takes the whole page down instead of one panel.
    _kind, _reason -> ""
  end

  defp blocks_by_reason do
    Orbit.Repo.query!(
      "SELECT reason, SUM(count) FROM geoip_denial_stats GROUP BY reason ORDER BY SUM(count) DESC"
    ).rows
    |> Enum.map(fn [reason, n] -> {reason, decimal_to_int(n)} end)
  rescue
    _ -> []
  catch
    # A pool checkout exits rather than raising; same fallback, or a stressed
    # database takes the whole page down instead of one panel.
    _kind, _reason -> []
  end

  defp decimal_to_int(%Decimal{} = d), do: Decimal.to_integer(d)
  defp decimal_to_int(n) when is_integer(n), do: n
  defp decimal_to_int(_), do: 0

  @impl true
  def handle_event("refresh_db", _params, %{assigns: %{refresh_busy: false}} = socket) do
    {:noreply,
     socket
     |> assign(refresh_busy: true)
     |> start_async(:refresh_db, fn -> Orbit.GeoIP.Updater.refresh() end)}
  end

  def handle_event("refresh_db", _params, %{assigns: %{refresh_busy: true}} = socket),
    do: {:noreply, socket}

  def handle_event("save", %{"cfg" => params}, socket) do
    enabled = params["enabled"] in ["true", "on"]
    countries = parse_countries(params["countries"])
    {entries, bad} = parse_whitelist(params["whitelist"])

    cond do
      bad != [] ->
        {:noreply,
         assign(socket, error: "invalid whitelist entries: #{Enum.join(bad, ", ")}", warning: nil)}

      Enum.any?(countries, &(String.length(&1) != 2)) ->
        {:noreply, assign(socket, error: "countries must be 2-letter ISO codes", warning: nil)}

      would_lock_self_out?(socket, enabled, countries, entries) and
          params["confirm_lockout"] != "true" ->
        {:noreply,
         assign(socket,
           error: nil,
           warning:
             "This config would BLOCK your own current IP — tick \"save anyway\" if that is intended (e.g. you are switching to VPN)."
         )}

      true ->
        Store.save_config(enabled, countries, entries, socket.assigns.current_user.username)

        Audit.write(
          action: "geoip.config.update",
          result: "ok",
          user_id: socket.assigns.current_user.id,
          detail: %{"name" => "geoip_config", "mode" => to_string(enabled)}
        )

        {:noreply, socket |> assign(error: nil, warning: nil) |> load()}
    end
  end

  defp parse_countries(raw) do
    to_string(raw || "")
    |> String.split(~r/[,\s]+/, trim: true)
    |> Enum.map(&String.upcase/1)
    |> Enum.uniq()
  end

  defp parse_whitelist(raw) do
    entries =
      to_string(raw || "")
      |> String.split(~r/\R/, trim: true)
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    bad = Enum.filter(entries, &(Rules.classify_entry(&1) == :error))
    {entries, bad}
  end

  # DR-G5 dry-run: would the operator's own socket IP be denied under the
  # NEW rules? DynDNS names cannot resolve synchronously here, so only
  # CIDR whitelist entries count — conservative (warns rather than misses).
  defp would_lock_self_out?(socket, enabled, countries, entries) do
    ip = socket_ip(socket)

    rules =
      Rules.parse_rules(enabled, Jason.encode!(countries), Jason.encode!(entries))

    db_ok = Lookup.db_available?()
    country = if db_ok, do: Lookup.country_for(ip)
    decision = Rules.decide(ip, rules, country, MapSet.new(), db_ok)
    ip != nil and not decision.allowed
  end

  # Proxy-aware viewer IP (honours DASH_TRUSTED_PROXY_HOPS) so both the
  # self-lockout dry-run and the "seen from" display evaluate the admin's real
  # IP, not the nginx container behind it.
  defp socket_ip(socket) do
    xff =
      case get_connect_info(socket, :x_headers) do
        headers when is_list(headers) ->
          Enum.find_value(headers, fn {name, value} -> name == "x-forwarded-for" && value end)

        _ ->
          nil
      end

    peer =
      case get_connect_info(socket, :peer_data) do
        %{address: address} -> address |> :inet.ntoa() |> to_string()
        _ -> nil
      end

    Orbit.Net.pick_client_ip(xff, peer)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:users} current_user={@current_user} />

      <section class="max-w-3xl p-6">
        <h1 class="flex items-center gap-2 mb-4 text-lg font-medium text-base-content">
          <Icons.icon name={:access_control} class="h-5 w-5 text-base-content/60" />
          Access control (GeoIP)
        </h1>

        <div class="mb-4 grid gap-3 text-sm md:grid-cols-3">
          <div class="rounded-lg border border-base-300 bg-base-200 p-3">
            <div class="text-xs text-base-content/60">GeoIP database</div>
            <div class={if @db_available, do: "text-primary", else: "text-error"}>
              {if @db_available, do: "loaded", else: "NOT available (gate fails open)"}
            </div>
            <div class="mt-1 text-xs text-base-content/60">
              last refresh: {refresh_text(@last_refresh)}
            </div>
            <div :if={@viewer_geo} class="mt-1 text-xs text-base-content/60">
              you are connecting from: <span class="text-base-content/80">{@viewer_geo}</span>
            </div>
            <button
              phx-click="refresh_db"
              disabled={@refresh_busy}
              class="mt-2 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300 disabled:opacity-50"
            >
              {if @refresh_busy, do: "Downloading…", else: "Refresh now"}
            </button>
          </div>
          <div class="rounded-lg border border-base-300 bg-base-200 p-3">
            <div class="text-xs text-base-content/60">CrowdSec blocklist</div>
            <div class={if @crowdsec.configured, do: "text-primary", else: "text-base-content/60"}>
              {if @crowdsec.configured,
                do: "#{@crowdsec.banned_count} bans · #{@crowdsec.detail}",
                else: "not configured"}
            </div>
          </div>
          <div class="rounded-lg border border-base-300 bg-base-200 p-3">
            <div class="text-xs text-base-content/60">Denials (all time)</div>
            <div :for={{reason, n} <- @blocks} class="text-xs text-base-content/80">
              {reason}: {n}
            </div>
            <div :if={@blocks == []} class="text-base-content/60">none</div>
          </div>
        </div>

        <div
          :if={@error}
          class="mb-4 rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>
        <div
          :if={@warning}
          class="mb-4 rounded border border-warning/40 bg-warning/10 p-2 text-sm text-warning"
        >
          {@warning}
        </div>

        <form phx-submit="save" class="rounded-lg border border-base-300 bg-base-200 p-4 text-sm">
          <label class="mb-3 flex items-center gap-2 text-base-content/80">
            <input type="hidden" name="cfg[enabled]" value="false" />
            <input
              type="checkbox"
              name="cfg[enabled]"
              value="true"
              checked={@enabled}
              class="accent-primary"
            /> Enforce country restriction
          </label>

          <label class="mb-3 block">
            <span class="mb-1 block text-xs text-base-content/60">
              Allowed countries (ISO codes, comma-separated; empty + empty whitelist = allow all)
            </span>
            <input name="cfg[countries]" value={@countries_text} class={input_cls()} />
          </label>

          <label class="mb-3 block">
            <span class="mb-1 block text-xs text-base-content/60">
              Whitelist — one CIDR/IP or DynDNS hostname per line (always allowed; beats the blocklist)
            </span>
            <textarea name="cfg[whitelist]" rows="5" class={input_cls()}>{@whitelist_text}</textarea>
          </label>

          <label :if={@warning} class="mb-3 flex items-center gap-2 text-warning">
            <input type="checkbox" name="cfg[confirm_lockout]" value="true" class="accent-warning" />
            save anyway (I know this blocks my current IP)
          </label>

          <button
            type="submit"
            class="rounded bg-primary px-4 py-1.5 text-sm text-primary-content hover:bg-primary/80"
          >
            Save
          </button>
        </form>

        <div :if={@resolved != []} class="mt-4 text-xs text-base-content/60">
          DynDNS whitelist currently resolves to: {Enum.join(@resolved, ", ")}
        </div>
      </section>
    </main>
    """
  end

  defp input_cls do
    "w-full rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end

  # Manual GeoLite2 refresh (AccessControlPage refreshDb parity) — the same
  # download the weekly scheduler job runs; idles without MaxMind creds.
  @impl true
  def handle_async(:refresh_db, {:ok, _outcome}, socket) do
    {:noreply, socket |> assign(refresh_busy: false) |> load()}
  end

  def handle_async(:refresh_db, {:exit, _}, socket) do
    {:noreply, socket |> assign(refresh_busy: false) |> load()}
  end

  defp refresh_text(%{at: nil}), do: "never"

  defp refresh_text(%{at: at, ok: ok, detail: detail}) do
    prefix = local_time_tag(at, "datetime")

    case ok do
      true -> [prefix, " — ok"]
      false -> [prefix, " — FAILED: ", detail]
      nil -> [prefix, " — ", detail]
    end
  end
end
