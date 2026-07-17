defmodule Orbit.LLM.Anonymize do
  @moduledoc """
  Scrub firewall-log text before it reaches an external LLM (invariant 4:
  only anonymized text leaves the box). Faithful port of
  backend/src/app/llm/anonymize.py — cross-checked against Python output
  vectors.

  Rules (deliberate, do not "anonymize harder"):
  - Internal/private IPs are KEPT (RFC1918, loopback, link-local, CGNAT,
    TEST-NET, ULA, …); only globally-routable IPs become consistent
    `PUBIP<n>` / `PUBIP6_<n>` pseudonyms.
  - MAC addresses keep their last two octets, the OUI is zeroed.
  - FQDNs become consistent `HOST<n>`; filename-like TLDs (log, conf, …) stay.
  - Secrets (key=value, PSK, Bearer, PEM blocks) become `REDACTED`.

  Pure + deterministic: pseudonym maps are per call, so equal input yields
  equal output and tokens correlate within one document.
  """

  import Bitwise

  @pem ~r/-----BEGIN [^-]+-----.*?-----END [^-]+-----/s
  @secret ~r/\b(password|passwd|pwd|secret|psk|pre-?shared[ _-]?key|api[_-]?key|token|bearer)\b(\s*[:=]\s*|\s+)("[^"]*"|'[^']*'|\S+)/i
  @mac ~r/\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/
  @ipv4 ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/
  @ipv6 ~r/(?<![\w:.])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(?![\w:.])/
  @fqdn ~r/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/

  @not_tld MapSet.new(
             ~w(log conf txt gz pid sock db pem crt cer key sh py js json yaml yml xml html css md arpa in-addr)
           )

  @doc "Return `text` with public IPs, MAC OUIs, FQDNs and secrets scrubbed."
  @spec anonymize(String.t()) :: String.t()
  def anonymize(text) when is_binary(text) do
    text
    |> redact_pem()
    |> redact_secrets()
    |> mask_macs()
    |> pseudonymize(@ipv4, &global_v4?/1, "PUBIP")
    |> pseudonymize(@ipv6, &global_v6?/1, "PUBIP6_")
    |> pseudonymize_fqdns()
  end

  defp redact_pem(text), do: Regex.replace(@pem, text, "REDACTED")

  defp redact_secrets(text) do
    Regex.replace(@secret, text, fn _full, label, sep, _value -> "#{label}#{sep}REDACTED" end)
  end

  defp mask_macs(text) do
    Regex.replace(@mac, text, fn mac ->
      octets = mac |> String.downcase() |> String.split(":")
      "00:00:00:00:" <> (octets |> Enum.drop(4) |> Enum.join(":"))
    end)
  end

  # Two-pass so the same token maps to the same pseudonym in first-seen order:
  # collect qualifying tokens, number them, then replace by lookup (non-matches
  # and non-qualifying tokens are returned unchanged).
  defp pseudonymize(text, regex, qualifies?, prefix) do
    map =
      regex
      |> Regex.scan(text)
      |> Enum.map(&hd/1)
      |> Enum.filter(qualifies?)
      |> Enum.uniq()
      |> Enum.with_index(1)
      |> Map.new(fn {tok, i} -> {tok, "#{prefix}#{i}"} end)

    Regex.replace(regex, text, fn tok -> Map.get(map, tok, tok) end)
  end

  defp pseudonymize_fqdns(text) do
    map =
      @fqdn
      |> Regex.scan(text)
      |> Enum.map(&hd/1)
      |> Enum.reject(&filename_like?/1)
      |> Enum.map(&String.downcase/1)
      |> Enum.uniq()
      |> Enum.with_index(1)
      |> Map.new(fn {host, i} -> {host, "HOST#{i}"} end)

    Regex.replace(@fqdn, text, fn tok ->
      if filename_like?(tok), do: tok, else: Map.get(map, String.downcase(tok), tok)
    end)
  end

  defp filename_like?(token) do
    token
    |> String.split(".")
    |> List.last()
    |> String.downcase()
    |> then(&MapSet.member?(@not_tld, &1))
  end

  # ipaddress.is_global parity: a token is pseudonymized only when it is a valid
  # address outside every special-purpose (non-global) range. Invalid tokens are
  # left untouched (Python returns them on ValueError).
  defp global_v4?(token) do
    case :inet.parse_ipv4_address(String.to_charlist(token)) do
      {:ok, {a, b, c, d}} -> not nonglobal_v4?(a * 16_777_216 + b * 65_536 + c * 256 + d)
      _ -> false
    end
  end

  defp nonglobal_v4?(n) do
    Enum.any?(nonglobal_v4_ranges(), fn {lo, hi} -> n >= lo and n <= hi end)
  end

  defp nonglobal_v4_ranges do
    [
      {i(0, 0, 0, 0), i(0, 255, 255, 255)},
      {i(10, 0, 0, 0), i(10, 255, 255, 255)},
      {i(100, 64, 0, 0), i(100, 127, 255, 255)},
      {i(127, 0, 0, 0), i(127, 255, 255, 255)},
      {i(169, 254, 0, 0), i(169, 254, 255, 255)},
      {i(172, 16, 0, 0), i(172, 31, 255, 255)},
      {i(192, 0, 0, 0), i(192, 0, 0, 255)},
      {i(192, 0, 2, 0), i(192, 0, 2, 255)},
      {i(192, 88, 99, 0), i(192, 88, 99, 255)},
      {i(192, 168, 0, 0), i(192, 168, 255, 255)},
      {i(198, 18, 0, 0), i(198, 19, 255, 255)},
      {i(198, 51, 100, 0), i(198, 51, 100, 255)},
      {i(203, 0, 113, 0), i(203, 0, 113, 255)},
      {i(224, 0, 0, 0), i(255, 255, 255, 255)}
    ]
  end

  defp i(a, b, c, d), do: a * 16_777_216 + b * 65_536 + c * 256 + d

  # Global v6 = GUA 2000::/3 minus the documentation block 2001:db8::/32; every
  # other address (loopback/link-local/ULA/multicast/…) is kept.
  defp global_v6?(token) do
    case :inet.parse_ipv6_address(String.to_charlist(token)) do
      {:ok, tuple} ->
        n = v6_int(tuple)
        bsr(n, 125) == 1 and bsr(n, 96) != 0x20010DB8

      _ ->
        false
    end
  end

  defp v6_int({a, b, c, d, e, f, g, h}) do
    ((((((a * 65_536 + b) * 65_536 + c) * 65_536 + d) * 65_536 + e) * 65_536 + f) * 65_536 + g) *
      65_536 + h
  end
end
