defmodule Orbit.Probe do
  @moduledoc """
  Out-of-band reachability probe — port of the deleted `probe/` package.

  This is the dashboard measuring the box ITSELF, from here, rather than
  believing what the box reports about itself. It is the only liveness signal
  for an agent-less device: a Securepoint or direct-polled box cannot tell us
  it is down, it simply stops answering.

  The target is the instance's `ping_url`, and its FORM decides what runs:

  - a bare host or IP (`10.1.2.3`, `fw.example.net`, `host:443`) → ICMP only
  - a full `http(s)://…` URL → ICMP to its hostname AND an HTTP GET

  The two axes are independent on purpose: a box can answer ICMP while its web
  service is down, which is a different, useful signal — not a single
  "reachable" boolean.
  """

  alias Orbit.Probe.HTTP
  alias Orbit.Probe.ICMP

  @type result :: %{
          icmp_up: boolean() | nil,
          http_up: boolean() | nil,
          rtt_ms: float() | nil,
          http_status: integer() | nil,
          error: String.t() | nil
        }

  @empty %{icmp_up: nil, http_up: nil, rtt_ms: nil, http_status: nil, error: nil}

  @doc "An untouched result — every axis nil means nothing was probed."
  def empty, do: @empty

  @doc "True when at least one axis actually ran."
  def probed?(%{icmp_up: nil, http_up: nil}), do: false
  def probed?(%{}), do: true

  @doc """
  Host to ICMP: a URL yields its hostname, a bare `host[:port]` yields the host.

  IPv6 literals are left alone — a single colon is a port, several are an
  address.
  """
  @spec target_host(String.t() | nil) :: String.t() | nil
  def target_host(nil), do: nil

  def target_host(ping_url) do
    case String.trim(ping_url) do
      "" ->
        nil

      v ->
        if String.contains?(v, "://") do
          case URI.parse(v).host do
            h when is_binary(h) and h != "" -> h
            _ -> nil
          end
        else
          if length(String.split(v, ":")) == 2, do: hd(String.split(v, ":", parts: 2)), else: v
        end
    end
  end

  defp url?(nil), do: false
  defp url?(v), do: v |> String.trim() |> String.starts_with?(["http://", "https://"])

  @doc """
  Probe one instance's `ping_url`. Never raises — an unprobeable target returns
  the empty result, so a missing setting is "not measured", never "down".
  """
  @spec run(String.t() | nil, keyword()) :: result()
  def run(ping_url, opts \\ []) do
    host = target_host(ping_url)

    cond do
      is_nil(host) ->
        @empty

      url?(ping_url) ->
        icmp = icmp_axis(host, opts)
        http = HTTP.get(String.trim(ping_url), opts)
        Map.merge(icmp, http)

      true ->
        icmp_axis(host, opts)
    end
  end

  defp icmp_axis(host, opts) do
    case ICMP.ping(host, timeout: Keyword.get(opts, :icmp_timeout, 2_000)) do
      {:ok, rtt} -> %{@empty | icmp_up: true, rtt_ms: rtt}
      {:error, reason} -> %{@empty | icmp_up: false, error: to_string(reason)}
    end
  end
end
