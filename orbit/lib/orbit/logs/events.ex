defmodule Orbit.Logs.Events do
  @moduledoc """
  Extract aggregated "critical" events from an agent log snapshot. Faithful
  port of backend/src/app/logs/events.py — cross-checked against Python output.

  Two syslog shapes: RFC5424 (`<PRI>` prefix, severity = PRI rem 8) and PRI-less
  BSD lines (curated pattern → severity). Lines are normalized (IPs, numbers,
  hex, quoted strings → placeholders) so repeats collapse into one counted
  event. Steady-state noise (dpinger sendto, filterdns resolve) is dropped.

  Severity rules are calibrated against real prod data — real fleets have zero
  sev<=2 lines, so never make crit-only the default anywhere.
  """

  @max_severity 4
  @pattern_max 200
  @sample_max 500

  @rfc5424 ~r/^<(?<pri>\d+)>\d+\s+(?<ts>\S+)\s+\S+\s+(?<app>\S+)\s+\S+\s+\S+\s+(?:\[[^\]]*\]\s*)?(?<msg>.*)$/
  @bsd ~r/^(?:<(?<pri>\d+)>)?(?<ts>[A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+\S+\s+(?<prog>[^\s:\[]+)(?:\[\d+\])?:\s*(?<msg>.*)$/

  @noise [~r/dpinger.*sendto error/i, ~r/filterdns.*failed to resolve/i]

  # First match wins; unmatched PRI-less lines are dropped.
  @curated [
    {~r/\bpanic\b|Fatal trap|out of swap/i, 2},
    {~r/authentication (?:error|failed)|Failed password|login failed/i, 3},
    {~r/\berror\b|\bcritical\b|\bcorrupt/i, 3},
    {~r/\bfail(?:ed|ure)?\b|\btimeout\b|link state changed to DOWN/i, 4}
  ]

  @kernel_subtag ~r/^(?<sub>[A-Z]{2,}[\w.-]*|[A-Za-z][\w.-]*_[\w.-]+):\s+(?<rest>\S.*)$/

  @days "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
  @months "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"

  @doc """
  Aggregate a snapshot's critical lines into normalized, counted events,
  sorted by severity then descending count. `log_name` is part of the
  contract (per-log rules belong here) but currently unused.
  """
  @spec extract_events(String.t(), String.t()) :: [map()]
  def extract_events(_log_name, content) when is_binary(content) do
    content
    |> String.split(~r/\r\n|\r|\n/)
    |> Enum.reduce({%{}, 0}, &fold_line/2)
    |> elem(0)
    |> Map.values()
    |> Enum.sort_by(&{&1.severity, -&1.count, &1.seq})
    |> Enum.map(&Map.delete(&1, :seq))
  end

  defp fold_line(line, {map, seq} = acc) do
    with true <- line != "",
         false <- Enum.any?(@noise, &Regex.match?(&1, line)),
         {sev, program, msg, ts} when sev <= @max_severity <- classify(line) do
      {program, msg} = resplit_kernel(program, msg)
      key = {sev, program, normalize(msg)}

      case Map.get(map, key) do
        nil ->
          event = %{
            severity: sev,
            program: String.slice(program, 0, 64),
            pattern: elem(key, 2),
            sample: String.slice(line, 0, @sample_max),
            count: 1,
            last_ts: ts,
            seq: seq
          }

          {Map.put(map, key, event), seq + 1}

        event ->
          updated = %{
            event
            | count: event.count + 1,
              sample: String.slice(line, 0, @sample_max),
              last_ts: ts
          }

          {Map.put(map, key, updated), seq}
      end
    else
      _ -> acc
    end
  end

  # {severity, program, message, ts} for one raw line, or nil to drop it.
  defp classify(line) do
    cond do
      caps = Regex.named_captures(@rfc5424, line) ->
        {rem(String.to_integer(caps["pri"]), 8), caps["app"], caps["msg"], caps["ts"]}

      caps = Regex.named_captures(@bsd, line) ->
        classify_bsd(line, caps)

      true ->
        nil
    end
  end

  defp classify_bsd(_line, %{"pri" => pri} = caps) when pri != "" do
    {rem(String.to_integer(pri), 8), caps["prog"], caps["msg"], caps["ts"]}
  end

  defp classify_bsd(line, caps) do
    Enum.find_value(@curated, fn {pattern, severity} ->
      if Regex.match?(pattern, line), do: {severity, caps["prog"], caps["msg"], caps["ts"]}
    end)
  end

  # Unify kernel-tagged dmesg lines with their raw (untagged) twins.
  defp resplit_kernel("kernel", msg) do
    case Regex.named_captures(@kernel_subtag, msg) do
      %{"sub" => sub, "rest" => rest} -> {sub, rest}
      nil -> {"kernel", msg}
    end
  end

  defp resplit_kernel(program, msg), do: {program, msg}

  @doc "Mask the variable parts of a log message so repeats collapse."
  @spec normalize(String.t()) :: String.t()
  def normalize(msg) do
    msg
    |> replace(~r/"[^"]*"/, ~S("…"))
    |> replace(~r{acme-challenge/[A-Za-z0-9_-]+}, "acme-challenge/…")
    |> replace(~r/orbit-\w+\.php/, "orbit-….php")
    |> replace(~r/\b\d+\.\d+\.\d+\.\d+\b/, "IP")
    |> replace(~r/\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b/, "MAC")
    |> replace(~r/\b[0-9a-fA-F:]*:[0-9a-fA-F:%a-z0-9]{4,}\b/, "IP6")
    |> replace(~r/\b0x[0-9a-fA-F]+\b/, "0xHEX")
    |> replace(~r/\b#{@days}\s+#{@months}\b/, "D M")
    |> replace(~r/(?<=\d\s)#{@months}\b/, "M")
    |> replace(~r/\b#{@months}(?=\s+\d)/, "M")
    |> replace(~r/(?<![\w.])-\d+\b/, "N")
    |> replace(~r/\b\d+\b/, "N")
    |> replace(~r/\s{2,}/, " ")
    |> String.slice(0, @pattern_max)
  end

  defp replace(text, regex, repl), do: Regex.replace(regex, text, repl)
end
