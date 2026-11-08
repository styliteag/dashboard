defmodule Orbit.Net.Egress do
  @moduledoc """
  Address policy for outbound requests to operator-supplied URLs (notifier
  webhooks, the LLM base URL).

  Blocked: loopback, link-local (incl. cloud metadata 169.254/16),
  unspecified, multicast and reserved (224/3), and the IPv6 forms that embed
  an IPv4 address — IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible `::a.b.c.d`,
  SIIT `::ffff:0:a.b.c.d`, NAT64 `64:ff9b::a.b.c.d` and the local-use NAT64
  prefix `64:ff9b:1::/48` (IPv4 in the last 32 bits, the usual /96 layout),
  and 6to4 `2002:aabb:ccdd::/48` — judged by the embedded address. RFC 1918 and
  ULA stay allowed on purpose: that is where firewalls and self-hosted
  services live.

  `ssrf_block_reason/1` resolves DNS names and checks every address. On its
  own that is a check, not a pin: a name that changes between the check and
  the connect (DNS rebinding) would slip through. So callers send the
  request through `pin/1`, which resolves once and connects to the vetted
  address, keeping the name for TLS SNI, certificate checks and the Host
  header. Callers also disable redirects so a vetted host cannot bounce the
  request elsewhere.

  Known limits: each distinct pinned host name gets its own Req/Finch pool
  (a `:hostname` connect option makes a separate pool), which is fine for
  the handful of operator-configured endpoints this serves. CGNAT
  (100.64/10, e.g. some cloud metadata services) and ULA (e.g. fd00:ec2::254)
  stay reachable by design, as do the /48-/64 layouts of 64:ff9b:1::/48.
  """

  import Bitwise

  @doc "True for an address tuple outbound calls must never reach."
  @spec blocked_addr?(:inet.ip_address()) :: boolean()
  def blocked_addr?({127, _, _, _}), do: true
  def blocked_addr?({169, 254, _, _}), do: true
  def blocked_addr?({0, _, _, _}), do: true
  def blocked_addr?({n, _, _, _}) when n >= 224, do: true
  def blocked_addr?({_, _, _, _}), do: false

  # ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible, deprecated) — the
  # latter also covers :: and ::1 (embedded 0.0.0.0 / 0.0.0.1).
  def blocked_addr?({0, 0, 0, 0, 0, w, hi, lo}) when w in [0, 0xFFFF], do: embedded(hi, lo)
  # SIIT ::ffff:0:a.b.c.d (RFC 7915).
  def blocked_addr?({0, 0, 0, 0, 0xFFFF, 0, hi, lo}), do: embedded(hi, lo)
  # NAT64 well-known prefix 64:ff9b::/96.
  def blocked_addr?({0x64, 0xFF9B, 0, 0, 0, 0, hi, lo}), do: embedded(hi, lo)
  # Local-use NAT64 64:ff9b:1::/48 (RFC 8215), judged as a /96 sub-prefix.
  def blocked_addr?({0x64, 0xFF9B, 1, _, _, _, hi, lo}), do: embedded(hi, lo)
  # 6to4 2002:aabb:ccdd::/48 (RFC 3056): the IPv4 sits right after 2002.
  def blocked_addr?({0x2002, hi, lo, _, _, _, _, _}), do: embedded(hi, lo)
  def blocked_addr?({w, _, _, _, _, _, _, _}) when band(w, 0xFFC0) == 0xFE80, do: true
  def blocked_addr?({w, _, _, _, _, _, _, _}) when w >= 0xFF00, do: true
  def blocked_addr?({_, _, _, _, _, _, _, _}), do: false
  def blocked_addr?(_), do: true

  defp embedded(hi, lo), do: blocked_addr?({hi >>> 8, hi &&& 0xFF, lo >>> 8, lo &&& 0xFF})

  @doc """
  Reject a URL whose scheme is not http(s) or whose host is, or resolves to,
  a blocked address. Returns a reason string or nil.
  """
  @spec ssrf_block_reason(String.t()) :: String.t() | nil
  def ssrf_block_reason(url) do
    case pin(url) do
      {:ok, _url, _connect_opts} -> nil
      {:error, reason} -> reason
    end
  end

  @doc """
  Resolve the URL's host once and vet every address. `{:ok, url, connect_opts}`
  has the host replaced by the first address and `connect_opts` carries
  `hostname: <original host>` for Req's `:connect_options` (SNI, certificate
  check, Host header), so the connect cannot land on a different address
  than the one checked. `{:error, reason}` otherwise. `resolve` is a test seam.
  """
  @spec pin(term(), (String.t() -> {:ok, [:inet.ip_address()]} | {:error, term()})) ::
          {:ok, String.t(), keyword()} | {:error, String.t()}
  def pin(url, resolve \\ &resolve_addrs/1)

  def pin(url, resolve) when is_binary(url) do
    uri = URI.parse(url)

    with true <- uri.scheme in ["http", "https"] and uri.host not in [nil, ""],
         {:ok, [first | _] = addrs} <- resolve.(uri.host),
         nil <- Enum.find_value(addrs, &blocked_reason/1) do
      pinned = %{uri | host: first |> :inet.ntoa() |> to_string()}
      {:ok, URI.to_string(pinned), [hostname: uri.host]}
    else
      false -> {:error, "URL must be http(s) with a host"}
      reason when is_binary(reason) -> {:error, reason}
      _ -> {:error, "host does not resolve"}
    end
  end

  def pin(_url, _resolve), do: {:error, "URL must be http(s) with a host"}

  @doc """
  Req options with `:url` pinned by `pin/1` (`:connect_options` gains
  `:hostname`). Options with a `:plug` (Req.Test) are returned unchanged:
  no network, nothing to pin.
  """
  @spec pin_req(keyword()) :: {:ok, keyword()} | {:error, String.t()}
  def pin_req(req_opts) do
    if Keyword.has_key?(req_opts, :plug) do
      {:ok, req_opts}
    else
      with {:ok, url, connect} <- pin(req_opts[:url]) do
        connect = Keyword.merge(Keyword.get(req_opts, :connect_options, []), connect)
        # An IPv6 literal only connects with inet6 on (Req defaults to inet).
        inet6 = if String.contains?(URI.parse(url).host, ":"), do: [inet6: true], else: []
        {:ok, Keyword.merge(req_opts, [url: url, connect_options: connect] ++ inet6)}
      end
    end
  end

  @doc """
  `Req.post/1` on the address `pin_req/1` vetted; `{:error, reason}` (a
  string) when the policy refuses the target.
  """
  @spec post(keyword()) :: {:ok, Req.Response.t()} | {:error, String.t() | Exception.t()}
  def post(req_opts) do
    with {:ok, pinned} <- pin_req(req_opts), do: Req.post(pinned)
  end

  @doc """
  Like `ssrf_block_reason/1` for a bare host name or IP literal (an SMTP
  relay): a reason string if it does not resolve or any of its addresses is
  blocked, else nil.
  """
  @spec host_block_reason(term()) :: String.t() | nil
  def host_block_reason(host) when is_binary(host) and host != "" do
    case resolve_addrs(host) do
      {:error, _} -> "host does not resolve"
      {:ok, addrs} -> Enum.find_value(addrs, &blocked_reason/1)
    end
  end

  def host_block_reason(_), do: "missing host"

  defp blocked_reason(addr) do
    if blocked_addr?(addr), do: "blocked address #{addr |> :inet.ntoa() |> to_string()}"
  end

  defp resolve_addrs(host) do
    chars = host |> String.trim_leading("[") |> String.trim_trailing("]") |> String.to_charlist()

    case :inet.parse_strict_address(chars) do
      {:ok, addr} ->
        {:ok, [addr]}

      {:error, _} ->
        v4 = :inet_res.lookup(chars, :in, :a, timeout: 5_000)
        v6 = :inet_res.lookup(chars, :in, :aaaa, timeout: 5_000)
        if v4 == [] and v6 == [], do: {:error, :nxdomain}, else: {:ok, v4 ++ v6}
    end
  end
end
