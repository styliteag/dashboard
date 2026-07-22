defmodule Orbit.Hub.Checkmk do
  @moduledoc """
  Turn a Linux node's raw Checkmk-agent output into the same section shapes
  the firewall agents push (agent_hub/checkmk.py port, §25/DR-10).

  On a generic Linux server the orbit agent collects nothing itself — it runs
  the vendored upstream `check_mk_agent` and ships its stdout as gzip+base64
  under `checkmk_raw` (pure transport, so the GPLv2 script stays untouched).
  Until this module existed the hub's `Map.take` dropped that section on the
  floor without a word, while the agent's own zero-filled `cpu`/`memory`/
  `loadavg` sections were stored as-is: a Linux node enrolled, connected,
  reported hostname and uptime, and showed a permanent 0 % CPU / 0 % RAM —
  indistinguishable from an idle machine rather than from a broken import.

  Only the sections that map onto an existing Orbit shape are parsed —
  `mem`, `kernel`, `cpu`, `df_v2`, `lnx_if`, `uptime`. Everything else
  Checkmk emits (systemd units, plugin inventories, …) is ignored on
  purpose: a section Orbit has no home for would only invent checks nobody
  asked for.

  Note the split the Checkmk agent makes: `<<<cpu>>>` is `/proc/loadavg`
  plus the core count (so it feeds *loadavg*, not utilisation), while the
  `/proc/stat` tick counters live inside `<<<kernel>>>`. Reading utilisation
  out of `<<<cpu>>>` finds nothing at all.

  CPU needs two pushes: those ticks are cumulative, so utilisation is the
  delta against the previous sample. The previous sample is kept per
  instance in the hub cache entry itself (`checkmk_cpu`), which means a
  restart costs exactly one cycle of CPU data and nothing else.
  """

  require Logger

  @max_decompressed 8 * 1024 * 1024

  @doc """
  Decode + parse one `checkmk_raw` payload into `{sections, cpu_state}`.

  `prev_cpu` is the `checkmk_cpu` map from the instance's last push (or nil).
  Returns `{%{}, prev_cpu}` for anything unusable — a corrupt or oversized
  payload must leave the cached values alone rather than blank the box.
  """
  @spec parse(map() | nil, map() | nil) :: {map(), map() | nil}
  def parse(payload, prev_cpu \\ nil)

  def parse(%{"output_gz_b64" => b64}, prev_cpu) when is_binary(b64) do
    with {:ok, gz} <- decode64(b64),
         {:ok, text} <- gunzip(gz) do
      sections = split_sections(text)
      {cpu, cpu_state} = cpu_section(sections["kernel"], prev_cpu)

      parsed =
        %{
          "memory" => mem_section(sections["mem"]),
          "cpu" => cpu,
          "disks" => df_section(sections["df_v2"]),
          "interfaces" => lnx_if_section(sections["lnx_if"]),
          "uptime" => uptime_section(sections["uptime"]),
          "loadavg" => loadavg_section(sections["cpu"]),
          "ntp" => chrony_section(sections["chrony"]),
          "services" => systemd_section(sections["systemd_units"])
        }
        |> Enum.reject(fn {_k, v} -> v in [nil, [], %{}] end)
        |> Map.new()

      {parsed, cpu_state}
    else
      {:error, reason} ->
        Logger.warning("checkmk.parse_failed reason=#{reason}")
        {%{}, prev_cpu}
    end
  end

  def parse(_payload, prev_cpu), do: {%{}, prev_cpu}

  @doc """
  Just the decompressed agent output text (nil when unusable). Used to retain
  the raw dump for the instance's Checkmk view — separate from `parse/2` so
  its callers and tests are untouched (the extra gunzip is cheap).
  """
  @spec raw_text(map() | nil) :: String.t() | nil
  def raw_text(%{"output_gz_b64" => b64}) when is_binary(b64) do
    with {:ok, gz} <- decode64(b64),
         {:ok, text} <- gunzip(gz) do
      text
    else
      _ -> nil
    end
  end

  def raw_text(_), do: nil

  # -- decoding ---------------------------------------------------------------

  defp decode64(b64) do
    case Base.decode64(b64) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, "bad base64"}
    end
  end

  # A zip bomb would otherwise be decompressed in full before we look at it.
  defp gunzip(gz) do
    text = :zlib.gunzip(gz)

    if byte_size(text) > @max_decompressed,
      do: {:error, "decompressed payload too large"},
      else: {:ok, text}
  rescue
    _ -> {:error, "bad gzip"}
  end

  @doc """
  Split Checkmk's `<<<section>>>` stream into `%{"name" => [lines]}`.

  A section header may carry options (`<<<lnx_if:sep(58)>>>`) and the same
  section can appear more than once (`df_v2` emits a second block for
  inodes) — options are dropped and repeats are concatenated, which matches
  how the upstream parsers read them.
  """
  def split_sections(text) when is_binary(text) do
    text
    |> String.split("\n")
    |> Enum.reduce({nil, %{}}, fn line, {current, acc} ->
      case section_header(line) do
        {:ok, name} -> {name, Map.put_new(acc, name, [])}
        :no -> {current, add_line(acc, current, line)}
      end
    end)
    |> elem(1)
    |> Map.new(fn {k, lines} -> {k, Enum.reverse(lines)} end)
  end

  defp section_header(line) do
    with true <- String.starts_with?(line, "<<<"),
         [name | _] <- line |> String.trim() |> String.trim_leading("<") |> String.split(">") do
      {:ok, name |> String.split(":", parts: 2) |> hd()}
    else
      _ -> :no
    end
  end

  defp add_line(acc, nil, _line), do: acc
  defp add_line(acc, section, line), do: Map.update(acc, section, [line], &[line | &1])

  # -- sections ---------------------------------------------------------------

  # <<<mem>>> is /proc/meminfo verbatim: "MemTotal:  1940712 kB".
  @doc false
  def mem_section(nil), do: nil

  def mem_section(lines) do
    values =
      for line <- lines,
          [key, rest] <- [String.split(line, ":", parts: 2)],
          {kb, _} <- [Integer.parse(String.trim(rest))],
          into: %{},
          do: {key, kb}

    total = values["MemTotal"]
    # MemAvailable is the honest "how much can a program still get" number —
    # MemFree alone counts cache as used and reports a healthy box at 95%.
    available = values["MemAvailable"] || values["MemFree"]

    if is_integer(total) and total > 0 and is_integer(available) do
      used_pct = (total - available) / total * 100.0
      swap_total = values["SwapTotal"] || 0
      swap_free = values["SwapFree"] || 0

      %{
        "total_mb" => round(total / 1024),
        "used_mb" => round((total - available) / 1024),
        "used_pct" => Float.round(used_pct, 1),
        "swap_total_mb" => round(swap_total / 1024),
        "swap_used_pct" => swap_used_pct(swap_total, swap_free)
      }
    end
  end

  defp swap_used_pct(total, free) when is_integer(total) and total > 0,
    do: Float.round((total - free) / total * 100.0, 1)

  defp swap_used_pct(_total, _free), do: 0.0

  # <<<cpu>>> line 1 = /proc/loadavg + core count, line 2 = jiffies total.
  # Utilisation is the delta of the busy jiffies against the previous push.
  @doc false
  def cpu_section(nil, prev), do: {nil, prev}

  def cpu_section(lines, prev) do
    case jiffies(lines) do
      nil ->
        {nil, prev}

      {busy, total} ->
        state = %{"busy" => busy, "total" => total}

        pct =
          case prev do
            %{"busy" => pb, "total" => pt} when is_number(pb) and is_number(pt) ->
              d_total = total - pt
              d_busy = busy - pb
              # A counter reset (reboot) or a repeated sample yields no usable
              # delta — report nothing rather than a spike or a fake 0%.
              if d_total > 0 and d_busy >= 0, do: Float.round(d_busy / d_total * 100.0, 1)

            _ ->
              nil
          end

        {if(pct, do: %{"total_pct" => pct}), state}
    end
  end

  # Inside <<<kernel>>>, /proc/stat's aggregate line keeps its label:
  # "cpu  user nice system idle iowait irq softirq steal …". The per-core
  # rows ("cpu0", "cpu1") are skipped — only the aggregate is wanted.
  defp jiffies(lines) do
    Enum.find_value(lines, fn line ->
      case String.split(line) do
        ["cpu" | rest] ->
          nums = for f <- rest, {n, ""} <- [Integer.parse(f)], do: n

          if length(nums) >= 5 do
            total = Enum.sum(nums)
            idle = Enum.at(nums, 3, 0) + Enum.at(nums, 4, 0)
            {total - idle, total}
          end

        _ ->
          nil
      end
    end)
  end

  # Line 1 of <<<cpu>>>: "0.08 0.08 0.09 1/156 507014 2" — the trailing field
  # is the core count.
  @doc false
  def loadavg_section(nil), do: nil

  def loadavg_section([first | _]) do
    case String.split(first) do
      [one, five, fifteen | rest] ->
        with {o, _} <- Float.parse(one),
             {f, _} <- Float.parse(five),
             {ft, _} <- Float.parse(fifteen) do
          %{"one" => o, "five" => f, "fifteen" => ft, "cores" => cores(rest)}
        else
          _ -> nil
        end

      _ ->
        nil
    end
  end

  def loadavg_section(_), do: nil

  defp cores(rest) do
    case rest |> List.last() |> to_string() |> Integer.parse() do
      {n, ""} when n > 0 -> n
      _ -> 0
    end
  end

  # <<<df_v2>>>: device fs total_kb used_kb avail_kb use% mountpoint.
  # The inode block ([df_inodes_start]…) and lsblk block are skipped.
  @doc false
  def df_section(nil), do: []

  def df_section(lines) do
    lines
    |> Enum.reduce({false, []}, fn line, {skipping, acc} ->
      cond do
        String.starts_with?(line, "[df_inodes_start]") or String.starts_with?(line, "[df_lsblk") ->
          {true, acc}

        String.starts_with?(line, "[df_inodes_end]") or
            String.starts_with?(line, "[df_lsblk_end]") ->
          {false, acc}

        skipping ->
          {true, acc}

        true ->
          {false, prepend_df(acc, line)}
      end
    end)
    |> elem(1)
    |> Enum.reverse()
    |> Enum.uniq_by(& &1["mountpoint"])
  end

  defp prepend_df(acc, line) do
    case String.split(line) do
      [device, _fs, total, used, _avail, pct, mount | _] ->
        with {total_kb, _} <- Integer.parse(total),
             {used_kb, _} <- Integer.parse(used),
             {used_pct, _} <- Integer.parse(String.trim_trailing(pct, "%")),
             true <- total_kb > 0 do
          [
            %{
              "device" => device,
              "mountpoint" => mount,
              "total_mb" => round(total_kb / 1024),
              "used_mb" => round(used_kb / 1024),
              "used_pct" => used_pct * 1.0
            }
            | acc
          ]
        else
          _ -> acc
        end

      _ ->
        acc
    end
  end

  # <<<lnx_if>>> carries an `ip link` dump plus a counter table
  # ("eth0: rx_bytes rx_packets … tx_bytes …"). Only the counter table maps
  # onto the interface shape the UI and the metric series already use.
  @doc false
  def lnx_if_section(nil), do: []

  def lnx_if_section(lines) do
    up = link_states(lines)

    for line <- lines,
        [name, rest] <- [String.split(line, ":", parts: 2)],
        name = String.trim(name),
        name != "",
        not String.contains?(name, " "),
        nums = for(f <- String.split(rest), {n, ""} <- [Integer.parse(f)], do: n),
        length(nums) >= 10 do
      %{
        "name" => name,
        "status" => if(Map.get(up, name, true), do: "up", else: "down"),
        "address" => nil,
        "bytes_received" => Enum.at(nums, 0, 0),
        "bytes_transmitted" => Enum.at(nums, 8, 0)
      }
    end
  end

  # "[eth0]" blocks end with "Link detected: yes|no".
  defp link_states(lines) do
    lines
    |> Enum.reduce({nil, %{}}, fn line, {current, acc} ->
      trimmed = String.trim(line)

      cond do
        String.starts_with?(trimmed, "[") and String.ends_with?(trimmed, "]") ->
          {trimmed |> String.trim_leading("[") |> String.trim_trailing("]"), acc}

        current && String.starts_with?(trimmed, "Link detected:") ->
          {current, Map.put(acc, current, String.contains?(trimmed, "yes"))}

        true ->
          {current, acc}
      end
    end)
    |> elem(1)
  end

  # <<<chrony>>> is `chronyc tracking` output. Mapped onto the same ntp shape
  # the FreeBSD boxes report, so ntp_check/1 works unchanged on Linux.
  @doc false
  def chrony_section(nil), do: nil

  def chrony_section(lines) do
    fields =
      for line <- lines,
          [k, v] <- [String.split(line, ":", parts: 2)],
          into: %{},
          do: {String.trim(k), String.trim(v)}

    with {stratum, _} <- Integer.parse(fields["Stratum"] || ""),
         true <- stratum > 0 do
      %{
        "stratum" => stratum,
        # "0.000057593 seconds fast of NTP time" → milliseconds.
        "offset_ms" => system_time_ms(fields["System time"]),
        "peer" => fields["Reference ID"],
        # Stratum 0 means "not synchronised" in chrony's own reporting; any
        # real stratum with a reference means the clock is disciplined.
        "synced" => true
      }
    else
      _ ->
        # chrony present but unsynchronised — WARN, never a missing check.
        if fields["Stratum"], do: %{"stratum" => 0, "synced" => false, "offset_ms" => 0.0}
    end
  end

  defp system_time_ms(nil), do: 0.0

  defp system_time_ms(text) do
    case Float.parse(String.trim(text)) do
      {secs, _} -> Float.round(secs * 1000, 3)
      :error -> 0.0
    end
  end

  # <<<systemd_units>>> [status] block: one "● unit.service" header per unit
  # followed by an indented "Active: <state> (...)" line. Only failed units
  # are reported — a service list of 400 units would drown the box's own
  # services view and emit hundreds of checks.
  @doc false
  def systemd_section(nil), do: []

  def systemd_section(lines) do
    lines
    |> Enum.reduce({nil, []}, fn line, {current, acc} ->
      trimmed = String.trim(line)

      cond do
        String.starts_with?(trimmed, "●") ->
          {trimmed |> String.trim_leading("●") |> String.trim() |> unit_name(), acc}

        current && String.starts_with?(trimmed, "Active:") ->
          failed? = String.contains?(trimmed, "failed")

          if failed?,
            do: {nil, [%{"name" => current, "description" => current, "running" => false} | acc]},
            else: {nil, acc}

        true ->
          {current, acc}
      end
    end)
    |> elem(1)
    |> Enum.reverse()
  end

  defp unit_name(header), do: header |> String.split(" ", parts: 2) |> hd()

  # <<<uptime>>>: "738381.32 1470462.76" — seconds since boot, idle seconds.
  #
  # Returns the SAME shape the firewall agent pushes: the human string
  # `uptime(1)` prints ("8 days, 12:33"), not a map. The detail page renders
  # this value directly, so a map crashed the whole Overview tab with a
  # Phoenix.HTML.Safe protocol error.
  @doc false
  def uptime_section(nil), do: nil

  def uptime_section([first | _]) do
    case first |> String.split() |> List.first() |> to_string() |> Float.parse() do
      {secs, _} when secs > 0 -> humanize_uptime(round(secs))
      _ -> nil
    end
  end

  def uptime_section(_), do: nil

  defp humanize_uptime(total) do
    days = div(total, 86_400)
    hours = total |> rem(86_400) |> div(3600)
    minutes = total |> rem(3600) |> div(60)
    clock = "#{hours}:#{String.pad_leading(to_string(minutes), 2, "0")}"

    case days do
      0 -> clock
      1 -> "1 day, #{clock}"
      n -> "#{n} days, #{clock}"
    end
  end
end
