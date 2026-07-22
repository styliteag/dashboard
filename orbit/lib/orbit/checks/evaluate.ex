defmodule Orbit.Checks.Evaluate do
  @moduledoc """
  Threshold logic: raw agent sections → [ServiceCheck]. Pure + DB-free, a
  port of checks/evaluate.py operating directly on the raw cache maps (no
  typed-converter layer — elixir maps pattern-match fine).

  Incident rules carried over verbatim (CLAUDE.md checks section):
  - NEVER emit a check for absent data — return nil on the no-data sentinels
    (swap_total_mb<=0, disk total unknown handled via fallback levels,
    cpu absent). Emitting a check on missing data crit'd fleets (c37de13).
  - CPU deliberately can NOT crit (spiky) — WARN ceiling.
  - UNKNOWN sorts below WARN (ServiceCheck.severity).

  Families here so far: memory, swap, cpu, disk. The rest (load, pf, ntp,
  gateway, ipsec, services, certs, connectivity, firmware) port next,
  alongside overlay + the export surfaces.
  """

  alias Orbit.Checks.ServiceCheck

  # Percent thresholds — identical to evaluate.py.
  @mem_warn 80.0
  @mem_crit 90.0
  @swap_warn 50.0
  @swap_crit 80.0
  @cpu_warn 95.0
  @disk_warn 80.0
  @disk_crit 90.0
  # ZFS pools degrade badly when full — warn earlier than a plain filesystem.
  @zfs_cap_warn 80
  @zfs_cap_crit 90
  # (min_gb, warn, crit) largest-first; disk levels scale with volume size.
  @disk_size_levels [{1024.0, 93.0, 97.0}, {200.0, 90.0, 95.0}, {50.0, 85.0, 93.0}]
  # Load is saturation (run-queue), normalised per core, 5-min average — CRIT
  # allowed (unlike CPU) but set high enough not to flap.
  @load_warn_per_core 2.0
  @load_crit_per_core 4.0
  @pf_warn 80.0
  @pf_crit 95.0
  @gw_loss_warn 20.0
  @gw_loss_crit 80.0
  @gw_down_words ~w(down force_down offline)
  @ipsec_up ~w(established installed connected up 1 true yes)
  @cert_warn_days 30
  @cert_crit_days 7
  @vital_services ~w(configd sshd)
  @dns_services ~w(dnsmasq unbound)

  @doc """
  Evaluate every family from a raw cache `status`/section map and return the
  non-nil checks. `sections` is the hub cache entry (raw agent sections).
  """
  @spec evaluate(map()) :: [ServiceCheck.t()]
  def evaluate(sections) when is_map(sections) do
    status = sections["status"] || sections

    [
      memory_check(status["memory"]),
      swap_check(status["memory"]),
      cpu_check(status["cpu"]),
      load_check(status["loadavg"]),
      pf_states_check(status["pf"]),
      ntp_check(status["ntp"]),
      collect_check(status["collect_ms"]),
      firmware_check(status["firmware"] || sections["firmware"])
    ]
    |> Enum.concat(disk_checks(status["disks"] || []))
    |> Enum.concat(iface_error_checks(status["interfaces"] || []))
    |> Enum.concat(gateway_checks(status["gateways"] || sections["gateways"] || []))
    |> Enum.concat(ipsec_checks(status["ipsec"] || sections["ipsec"]))
    |> Enum.concat(service_checks(status["services"] || sections["services"] || []))
    |> Enum.concat(cert_checks(status["certificates"] || sections["certificates"] || []))
    |> Enum.concat(connectivity_checks(status["connectivity"] || sections["connectivity"] || []))
    |> Enum.concat(zfs_checks(status["zfs"]))
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  ZFS checks from the Checkmk `zpool`/`zfsget` sections (linux nodes). `[]`
  when the box has no ZFS — no-data never emits a check.

  Per pool: ONLINE is OK; any other known pool state is CRIT (redundancy lost
  or worse); an unrecognised state is UNKNOWN. Capacity warns at 80 %, crit
  90 %. Per dataset: only datasets that carry a quota **and** sit near it
  (>= warn) emit `zfs:<dataset>` — a quota'd share filling up is the operator
  concern; unquota'd datasets and slack ones never clutter the surface.
  """
  def zfs_checks(%{} = zfs) do
    pools = Map.get(zfs, "pools", [])
    pool_names = MapSet.new(pools, & &1["name"])

    pool_checks = Enum.map(pools, &zfs_pool_check/1)

    dataset_checks =
      zfs
      |> Map.get("datasets", [])
      |> Enum.filter(&dataset_near_quota?/1)
      # A quota on the pool's root dataset shares the pool's `zfs:<name>` key —
      # let the pool check own it rather than emit a duplicate service.
      |> Enum.reject(fn d -> MapSet.member?(pool_names, d["name"]) end)
      |> Enum.map(&zfs_dataset_check/1)

    pool_checks ++ dataset_checks
  end

  def zfs_checks(_), do: []

  defp dataset_near_quota?(%{"quota" => q, "used" => u})
       when is_integer(q) and q > 0 and is_integer(u),
       do: u / q * 100 >= @zfs_cap_warn

  defp dataset_near_quota?(_), do: false

  defp zfs_dataset_check(%{"name" => name, "quota" => quota, "used" => used}) do
    pct = round(used / quota * 100)
    {state, _} = level(pct, @zfs_cap_warn, @zfs_cap_crit)

    %ServiceCheck{
      key: "zfs:#{name}",
      state: state,
      summary: "Dataset #{name} #{pct}% of quota",
      metrics: [
        ServiceCheck.metric("zfs_quota_pct", pct,
          warn: @zfs_cap_warn,
          crit: @zfs_cap_crit,
          unit: "%"
        )
      ]
    }
  end

  defp zfs_pool_check(%{"name" => name} = p) do
    cap = p["cap_pct"]
    frag = p["frag_pct"]
    {health_state, health_word} = zfs_health(p["health"])

    {cap_state, _} =
      if is_integer(cap),
        do: level(cap, @zfs_cap_warn, @zfs_cap_crit),
        else: {ServiceCheck.ok(), "ok"}

    cap_txt = if is_integer(cap), do: ", #{cap}% full", else: ""
    frag_txt = if is_integer(frag), do: ", #{frag}% frag", else: ""

    metrics =
      if is_integer(cap) do
        [
          ServiceCheck.metric("zfs_cap_pct", cap,
            warn: @zfs_cap_warn,
            crit: @zfs_cap_crit,
            unit: "%"
          )
        ]
      else
        []
      end

    %ServiceCheck{
      key: "zfs:#{name}",
      state: worse(health_state, cap_state),
      summary: "Pool #{name} #{health_word}#{cap_txt}#{frag_txt}",
      metrics: metrics
    }
  end

  defp zfs_health("ONLINE"), do: {ServiceCheck.ok(), "ONLINE"}

  defp zfs_health(h) when h in ~w(DEGRADED FAULTED OFFLINE UNAVAIL REMOVED SUSPENDED),
    do: {ServiceCheck.crit(), h}

  defp zfs_health(h), do: {ServiceCheck.unknown(), h || "unknown"}

  defp worse(a, b),
    do: if(ServiceCheck.severity(a) >= ServiceCheck.severity(b), do: a, else: b)

  @doc "Memory used-% check. nil when no memory section."
  def memory_check(nil), do: nil

  def memory_check(%{"used_pct" => pct}) when is_number(pct) do
    {state, word} = level(pct, @mem_warn, @mem_crit)

    %ServiceCheck{
      key: "memory",
      state: state,
      summary: "Memory #{round(pct)}% used (#{word})",
      metrics: [
        ServiceCheck.metric("mem_used_pct", pct, warn: @mem_warn, crit: @mem_crit, unit: "%")
      ]
    }
  end

  def memory_check(_), do: nil

  @doc "Swap-in-use check. nil when the box reports no swap device (no data)."
  def swap_check(%{"swap_total_mb" => total, "swap_used_pct" => pct})
      when is_number(total) and total > 0 and is_number(pct) do
    {state, word} = level(pct, @swap_warn, @swap_crit)

    %ServiceCheck{
      key: "swap",
      state: state,
      summary: "Swap #{round(pct)}% used (#{word})",
      metrics: [
        ServiceCheck.metric("swap_used_pct", pct, warn: @swap_warn, crit: @swap_crit, unit: "%")
      ]
    }
  end

  def swap_check(_), do: nil

  @doc "CPU check. nil when no cpu section. CPU can WARN but NEVER crit (spiky)."
  def cpu_check(%{"total_pct" => pct}) when is_number(pct) do
    state = if pct >= @cpu_warn, do: ServiceCheck.warn(), else: ServiceCheck.ok()

    %ServiceCheck{
      key: "cpu",
      state: state,
      summary: "CPU #{round(pct)}%",
      metrics: [ServiceCheck.metric("cpu_used_pct", pct, warn: @cpu_warn, unit: "%")]
    }
  end

  def cpu_check(_), do: nil

  @doc "One check per mounted volume; levels scale with volume size."
  def disk_checks(disks) when is_list(disks) do
    for d <- disks, is_number(d["used_pct"]) do
      label = d["mountpoint"] || d["device"] || "?"
      pct = d["used_pct"]
      {warn, crit} = disk_levels(d["total_mb"])
      {state, word} = level(pct, warn, crit)
      free = free_text(d["total_mb"], pct)

      %ServiceCheck{
        key: "disk:#{label}",
        state: state,
        summary: "Disk #{label} #{round(pct)}% used (#{word}#{free})",
        metrics: [ServiceCheck.metric("disk_used_pct", pct, warn: warn, crit: crit, unit: "%")]
      }
    end
  end

  @doc """
  5-min load average normalised per core. nil when no data (cores<=0: direct
  poll or a pre-1.8.1 agent). CRIT allowed (saturation, not utilization).
  """
  def load_check(%{"five" => five, "cores" => cores})
      when is_number(five) and is_number(cores) and cores > 0 do
    per_core = five / cores
    {state, word} = level(per_core, @load_warn_per_core, @load_crit_per_core)

    %ServiceCheck{
      key: "load",
      state: state,
      summary: "Load #{f2(five)} (5m) = #{f2(per_core)}/core over #{cores} cores (#{word})",
      metrics: [
        ServiceCheck.metric("load_per_core", Float.round(per_core / 1, 2),
          warn: @load_warn_per_core,
          crit: @load_crit_per_core
        ),
        ServiceCheck.metric("load5", five)
      ]
    }
  end

  def load_check(_), do: nil

  @doc "pf state-table fill. nil when no data (states_limit<=0, e.g. direct poll)."
  def pf_states_check(%{"states_limit" => lim, "states_pct" => pct, "states_current" => cur})
      when is_number(lim) and lim > 0 and is_number(pct) do
    {state, word} = level(pct, @pf_warn, @pf_crit)

    %ServiceCheck{
      key: "pf_states",
      state: state,
      summary: "pf states #{cur}/#{lim} (#{round(pct)}%, #{word})",
      metrics: [
        ServiceCheck.metric("pf_states_pct", pct, warn: @pf_warn, crit: @pf_crit, unit: "%"),
        ServiceCheck.metric("pf_states", cur * 1.0)
      ]
    }
  end

  def pf_states_check(_), do: nil

  @doc """
  NTP sync. nil when no data (stratum<0). A reachable-but-unsynced clock is
  WARN, never CRIT — a freshly booted box must not read red.
  """
  def ntp_check(%{"stratum" => stratum} = ntp) when is_number(stratum) and stratum >= 0 do
    if ntp["synced"] do
      peer = if ntp["peer"] not in [nil, ""], do: " via #{ntp["peer"]}", else: ""
      offset = ntp["offset_ms"] || 0.0

      %ServiceCheck{
        key: "ntp",
        state: ServiceCheck.ok(),
        summary: "NTP synced (stratum #{stratum}, offset #{f1(offset)}ms)#{peer}",
        metrics: [ServiceCheck.metric("ntp_offset_ms", offset, unit: "ms")]
      }
    else
      %ServiceCheck{
        key: "ntp",
        state: ServiceCheck.warn(),
        summary: "NTP not synchronised (no usable peer yet)"
      }
    end
  end

  def ntp_check(_), do: nil

  # Error rate as a percentage of total packets. Both counters are cumulative
  # since boot, so this is the lifetime error ratio, not a point-in-time rate.
  @iface_err_warn 0.05
  @iface_err_crit 0.1

  @doc """
  Per-interface error rate.

  The `iface_errors:*` family was registered everywhere — selection
  categories, the export tree, the aggregate map, even the flap-debounce
  prefix list — but nothing ever emitted a check for it. The counters have
  always been in the push and on the Network tab.

  A raw error count is not comparable across links: a busy 10G port passes
  orders of magnitude more frames than a mgmt link, so the same "thousands of
  errors" is routine on one and a dying transceiver on another. So this grades
  the error *rate* — errors as a percentage of total packets — WARN at
  #{@iface_err_warn}%, CRIT at #{@iface_err_crit}%.

  Returns nothing (never a fake zero) when the box reports no error counters
  or no packet counters (Securepoint, some poll paths), or when the link has
  carried no packets to rate against. An interface that is down is skipped —
  its errors are a symptom of the outage, not a second incident.
  """
  def iface_error_checks(interfaces) when is_list(interfaces) do
    for iface <- interfaces,
        is_map(iface),
        name = presence(iface["name"]),
        iface["status"] in [nil, "up", "up (not running)"],
        rate = iface_error_rate(iface),
        rate != nil do
      {state, word} = level(rate, @iface_err_warn, @iface_err_crit)
      errors = iface_error_total(iface)
      packets = iface_packet_total(iface)

      %ServiceCheck{
        key: "iface_errors:#{name}",
        state: state,
        summary:
          "Interface #{name} #{fmt_rate(rate)}% error rate " <>
            "(#{errors} err / #{packets} pkts since boot, #{word})",
        metrics: [
          ServiceCheck.metric("iface_error_rate", rate,
            warn: @iface_err_warn,
            crit: @iface_err_crit,
            unit: "%"
          )
        ]
      }
    end
  end

  def iface_error_checks(_), do: []

  # Errors as a % of total packets, or nil when the rate cannot be formed:
  # error counters absent, packet counters absent, or no packets carried yet
  # (an idle link's lone error would otherwise read as a div-by-zero spike).
  defp iface_error_rate(iface) do
    with errors when is_integer(errors) <- iface_error_total(iface),
         packets when is_integer(packets) and packets > 0 <- iface_packet_total(iface) do
      errors / packets * 100
    else
      _ -> nil
    end
  end

  # Absent counters ⇒ nil (no check). Present-but-zero is a real zero.
  defp iface_error_total(iface) do
    case {iface["in_errors"], iface["out_errors"]} do
      {nil, nil} -> nil
      {in_e, out_e} -> num(in_e) + num(out_e)
    end
  end

  defp iface_packet_total(iface) do
    case {iface["in_packets"], iface["out_packets"]} do
      {nil, nil} -> nil
      {in_p, out_p} -> num(in_p) + num(out_p)
    end
  end

  # Shortest readable form of the rate for the summary; 3 decimals resolves the
  # 0.05/0.1 lines and Elixir drops any trailing zeros.
  defp fmt_rate(rate), do: Float.round(rate, 3)

  defp num(v) when is_number(v), do: trunc(v)
  defp num(_), do: 0

  defp presence(name) when is_binary(name) do
    case String.trim(name) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp presence(_), do: nil

  @collect_warn_ms 10_000

  @doc """
  How long the agent's collect cycle takes.

  A cycle creeping toward the push interval means a collector is hanging (a
  wedged pkg fetch, an unreachable NTP peer, a slow API) and the box's data
  is going stale even though the agent still looks connected. The detail
  page has always drawn this with a 10s reference line; without a check the
  degradation raised nothing on Alerts or in the exports.

  WARN only, never CRIT — a slow cycle is not an outage, and CPU-style "can
  degrade but not page" is the established convention here. No data (a
  direct-polled box has no agent) returns nil, never a fake OK.
  """
  def collect_check(ms) when is_number(ms) and ms > 0 do
    state = if ms >= @collect_warn_ms, do: ServiceCheck.warn(), else: ServiceCheck.ok()
    word = if ms >= @collect_warn_ms, do: "slow", else: "ok"

    %ServiceCheck{
      key: "agent.collect",
      state: state,
      summary: "Agent collect cycle #{f1(ms / 1000)}s (#{word})",
      metrics: [
        ServiceCheck.metric("collect_seconds", ms / 1000,
          warn: @collect_warn_ms / 1000,
          unit: "s"
        )
      ]
    }
  end

  def collect_check(_), do: nil

  @doc "One check per gateway. Down status word ⇒ CRIT; loss 20/80."
  def gateway_checks(gateways) when is_list(gateways) do
    for g <- gateways, is_map(g) do
      name = g["name"] || "?"
      st = (g["status"] || "") |> to_string() |> String.downcase()
      loss = loss_pct(g["loss"])

      {state, word} =
        cond do
          Enum.any?(@gw_down_words, &String.contains?(st, &1)) ->
            {ServiceCheck.crit(), "down"}

          is_number(loss) and loss >= @gw_loss_crit ->
            {ServiceCheck.crit(), "loss #{round(loss)}%"}

          is_number(loss) and loss >= @gw_loss_warn ->
            {ServiceCheck.warn(), "loss #{round(loss)}%"}

          true ->
            {ServiceCheck.ok(), "online"}
        end

      metrics =
        if is_number(loss),
          do: [
            ServiceCheck.metric("gw_loss_pct", loss,
              warn: @gw_loss_warn,
              crit: @gw_loss_crit,
              unit: "%"
            )
          ],
          else: []

      %ServiceCheck{
        key: "gateway:#{name}",
        state: state,
        summary: "Gateway #{name} #{word}",
        metrics: metrics
      }
    end
  end

  def gateway_checks(_), do: []

  @doc """
  IPsec service + per-tunnel + per-Phase-2-ping checks.

  The service check is emitted ONLY when the box has tunnels configured — a
  box with no IPsec legitimately runs no strongSwan, so "service not running"
  there is a permanent false CRIT (incident c37de13: ipsec.service crit'd the
  fleet on non-IPsec boxes). Configured tunnels stay listed even when the
  daemon is down, so a genuine crash on an IPsec box still surfaces.
  """
  def ipsec_checks(%{"tunnels" => tunnels} = ipsec) when is_list(tunnels) do
    service =
      if tunnels != [] do
        [
          %ServiceCheck{
            key: "ipsec.service",
            state: if(ipsec["running"], do: ServiceCheck.ok(), else: ServiceCheck.crit()),
            summary:
              if(ipsec["running"], do: "IPsec service running", else: "IPsec service NOT running")
          }
        ]
      else
        []
      end

    service ++ Enum.flat_map(tunnels, &tunnel_checks/1)
  end

  def ipsec_checks(_), do: []

  defp tunnel_checks(t) do
    status = (t["status"] || "") |> to_string() |> String.trim() |> String.downcase()
    up = status in @ipsec_up
    label = t["description"] || t["id"] || "?"

    tunnel = %ServiceCheck{
      key: "ipsec.tunnel:#{label}",
      state: if(up, do: ServiceCheck.ok(), else: ServiceCheck.crit()),
      summary: "Tunnel #{label} #{if up, do: "up", else: "down"} (#{t["status"]})"
    }

    [tunnel | ping_checks(label, t["children"] || [])]
  end

  # Per-Phase-2 ping monitor: a configured ping with no reply is CRIT even when
  # the child SA is INSTALLED (an installed-but-not-passing tunnel is a
  # problem); a misconfigured probe is WARN, not a false outage; unconfigured
  # children (ping_state "none") are skipped.
  defp ping_checks(label, children) when is_list(children) do
    for ch <- children,
        (ch["ping_state"] || "none") |> to_string() |> String.downcase() != "none" do
      ps = ch["ping_state"] |> to_string() |> String.downcase()
      selector = ch["remote_ts"] || ch["name"] || "?"

      {state, word} =
        case ps do
          "ok" -> {ServiceCheck.ok(), "ping ok"}
          "fail" -> {ServiceCheck.crit(), "ping FAILED (no reply)"}
          _ -> {ServiceCheck.warn(), "ping error (check source/destination)"}
        end

      metrics =
        [
          if(is_number(ch["ping_loss_pct"]),
            do: ServiceCheck.metric("ping_loss_pct", ch["ping_loss_pct"], unit: "%")
          ),
          if(is_number(ch["ping_rtt_ms"]),
            do: ServiceCheck.metric("ping_rtt_ms", ch["ping_rtt_ms"], unit: "ms")
          )
        ]
        |> Enum.reject(&is_nil/1)

      %ServiceCheck{
        key: "ipsec.tunnel_ping:#{label}/#{selector}",
        state: state,
        summary: "Tunnel #{label} P2 #{selector} #{word}",
        metrics: metrics
      }
    end
  end

  defp ping_checks(_, _), do: []

  @doc """
  Firmware check. Security updates ⇒ WARN, a failed check ⇒ WARN (never a
  green "up to date"), routine non-security updates ⇒ OK but counted (§25),
  else OK. nil when no firmware section.
  """
  def firmware_check(nil), do: nil

  def firmware_check(fw) when is_map(fw) do
    cond do
      fw["upgrade_available"] && to_number(fw["security_updates"]) > 0 ->
        fw_check(
          ServiceCheck.warn(),
          "#{fw["security_updates"]} security update(s) pending (#{fw["updates_available"]} total)"
        )

      fw["upgrade_available"] ->
        fw_check(
          ServiceCheck.warn(),
          "Update available: #{fw["product_version"]} → #{fw["product_latest"] || "?"}"
        )

      fw["check_failed"] ->
        fw_check(
          ServiceCheck.warn(),
          "Firmware update check failed (#{fw["product_version"]} installed)"
        )

      to_number(fw["updates_available"]) > 0 ->
        fw_check(
          ServiceCheck.ok(),
          "#{fw["updates_available"]} update(s) pending, none security-relevant"
        )

      true ->
        fw_check(ServiceCheck.ok(), "Firmware up to date (#{fw["product_version"]})")
    end
  end

  def firmware_check(_), do: nil

  defp fw_check(state, summary),
    do: %ServiceCheck{key: "firmware", state: state, summary: summary}

  @doc """
  Vital-service checks (only services actually present — an absent service
  never invents a red check). DNS is a group: CRIT only when NO resolver
  runs. Linux systemd failed units ⇒ WARN (degradation, unknown blast radius).
  """
  def service_checks([]), do: []

  def service_checks(services) when is_list(services) do
    by_name = Map.new(services, &{&1["name"], &1})

    vital =
      for name <- @vital_services, svc = by_name[name], svc != nil do
        %ServiceCheck{
          key: "service:#{name}",
          state: if(svc["running"], do: ServiceCheck.ok(), else: ServiceCheck.crit()),
          summary: "Service #{name} #{if svc["running"], do: "running", else: "STOPPED"}"
        }
      end

    dns = Enum.filter(@dns_services, &Map.has_key?(by_name, &1))

    dns_check =
      if dns != [] do
        running = Enum.any?(dns, &by_name[&1]["running"])

        [
          %ServiceCheck{
            key: "service:dns",
            state: if(running, do: ServiceCheck.ok(), else: ServiceCheck.crit()),
            summary: if(running, do: "DNS resolver running", else: "No DNS resolver running")
          }
        ]
      else
        []
      end

    seen = MapSet.new(vital ++ dns_check, & &1.key)

    failed =
      for svc <- services, svc["failed"], "service:#{svc["name"]}" not in seen do
        %ServiceCheck{
          key: "service:#{svc["name"]}",
          state: ServiceCheck.warn(),
          summary: "Unit #{svc["name"]} failed"
        }
      end

    vital ++ dns_check ++ failed
  end

  def service_checks(_), do: []

  @doc "Certificate-expiry checks. CRIT when expired or <7d, WARN <30d."
  def cert_checks(certs) when is_list(certs) do
    for c <- certs, is_number(c["days_remaining"]) do
      days = c["days_remaining"]

      {state, word} =
        cond do
          days < @cert_crit_days ->
            {ServiceCheck.crit(), if(days < 0, do: "EXPIRED", else: "expires in #{days}d")}

          days < @cert_warn_days ->
            {ServiceCheck.warn(), "expires in #{days}d"}

          true ->
            {ServiceCheck.ok(), "valid for #{days}d"}
        end

      label = c["name"] || c["refid"] || "certificate"
      gui = if c["is_gui"], do: " [GUI]", else: ""

      %ServiceCheck{
        key: "cert:#{c["refid"] || label}",
        state: state,
        summary: "Certificate #{label}#{gui} #{word}",
        metrics: [
          ServiceCheck.metric("cert_days_remaining", days * 1.0,
            warn: @cert_warn_days * 1.0,
            crit: @cert_crit_days * 1.0,
            unit: "d"
          )
        ]
      }
    end
  end

  def cert_checks(_), do: []

  @doc """
  Standalone connectivity-ping checks (one per monitor). Same categorical
  semantics as the IPsec P2 ping: no reply ⇒ CRIT, misconfigured ⇒ WARN,
  unevaluated (ping_state 'none') skipped. Keyed by monitor id.
  """
  def connectivity_checks(results) when is_list(results) do
    for r <- results, (r["ping_state"] || "none") |> to_string() |> String.downcase() != "none" do
      ps = r["ping_state"] |> to_string() |> String.downcase()
      label = r["name"] || r["destination"] || to_string(r["id"])

      {state, word} =
        case ps do
          "ok" -> {ServiceCheck.ok(), "ping ok"}
          "fail" -> {ServiceCheck.crit(), "ping FAILED (no reply)"}
          _ -> {ServiceCheck.warn(), "ping error (check source/destination)"}
        end

      metrics =
        [
          if(is_number(r["ping_loss_pct"]),
            do: ServiceCheck.metric("ping_loss_pct", r["ping_loss_pct"], unit: "%")
          ),
          if(is_number(r["ping_rtt_ms"]),
            do: ServiceCheck.metric("ping_rtt_ms", r["ping_rtt_ms"], unit: "ms")
          )
        ]
        |> Enum.reject(&is_nil/1)

      %ServiceCheck{
        key: "connectivity:#{r["id"]}",
        state: state,
        summary: "Connectivity #{label} → #{r["destination"]} #{word}",
        metrics: metrics
      }
    end
  end

  def connectivity_checks(_), do: []

  defp to_number(n) when is_number(n), do: n
  defp to_number(_), do: 0

  # Parse a gateway loss string like "0.0%" / "100%" → float, else nil.
  defp loss_pct(raw) when is_binary(raw) do
    case raw |> String.trim() |> String.trim_trailing("%") |> String.trim() |> Float.parse() do
      {v, _} -> v
      :error -> nil
    end
  end

  defp loss_pct(raw) when is_number(raw), do: raw / 1
  defp loss_pct(_), do: nil

  defp f1(x) when is_number(x), do: :erlang.float_to_binary(x / 1, decimals: 1)
  defp f2(x) when is_number(x), do: :erlang.float_to_binary(x / 1, decimals: 2)

  # (warn, crit) used-% levels for a volume of the given size.
  defp disk_levels(total_mb) when is_number(total_mb) and total_mb > 0 do
    gb = total_mb / 1024.0

    Enum.find_value(@disk_size_levels, {@disk_warn, @disk_crit}, fn {min_gb, warn, crit} ->
      if gb >= min_gb, do: {warn, crit}
    end)
  end

  defp disk_levels(_), do: {@disk_warn, @disk_crit}

  defp free_text(total_mb, pct) when is_number(total_mb) and total_mb > 0 do
    gb_free = total_mb * (100.0 - pct) / 100.0 / 1024.0
    ", #{:erlang.float_to_binary(gb_free, decimals: 1)} GB free"
  end

  defp free_text(_, _), do: ""

  defp level(pct, warn, crit) do
    cond do
      pct >= crit -> {ServiceCheck.crit(), "critical"}
      pct >= warn -> {ServiceCheck.warn(), "high"}
      true -> {ServiceCheck.ok(), "ok"}
    end
  end
end
