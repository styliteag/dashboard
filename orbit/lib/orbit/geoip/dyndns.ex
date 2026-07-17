defmodule Orbit.GeoIP.Dyndns do
  @moduledoc """
  Background resolver for DynDNS whitelist entries (DR-G4): every 5 minutes
  each hostname is resolved (A and AAAA); the gate checks against the last
  resolved set via `resolved_ips/0` (:persistent_term — the request path
  never does DNS). Resolution failures keep the host's last known IPs —
  flapping DNS must not lock an operator out. Deliberate tradeoff (ADR):
  whoever controls the entry's DNS zone controls the bypass.
  """

  use GenServer

  @interval_ms 5 * 60_000
  @ips_key {__MODULE__, :ips}

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "The union of all last-resolved whitelist-hostname IPs."
  def resolved_ips do
    :persistent_term.get(@ips_key, MapSet.new())
  end

  @doc "Prompt re-resolve (config just changed); no-op when not running."
  def refresh(server \\ __MODULE__) do
    GenServer.cast(server, :refresh)
  catch
    :exit, _ -> :ok
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    # First resolve happens async right away; boot must not block on DNS.
    send(self(), :resolve)
    {:ok, %{by_host: %{}}}
  end

  @impl true
  def handle_cast(:refresh, state), do: {:noreply, resolve(state)}

  @impl true
  def handle_info(:resolve, state) do
    Process.send_after(self(), :resolve, @interval_ms)
    {:noreply, resolve(state)}
  end

  defp resolve(state) do
    hostnames = Orbit.GeoIP.Store.current_rules().hostnames

    by_host =
      Map.new(hostnames, fn host ->
        case lookup(host) do
          [] -> {host, Map.get(state.by_host, host, [])}
          ips -> {host, ips}
        end
      end)

    union = by_host |> Map.values() |> List.flatten() |> MapSet.new()
    :persistent_term.put(@ips_key, union)
    %{state | by_host: by_host}
  end

  defp lookup(host) do
    chars = String.to_charlist(host)

    for type <- [:a, :aaaa],
        addr <- :inet_res.lookup(chars, :in, type, timeout: 5_000),
        do: addr |> :inet.ntoa() |> to_string()
  catch
    _, _ -> []
  end
end
