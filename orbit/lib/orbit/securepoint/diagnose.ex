defmodule Orbit.Securepoint.Diagnose do
  @moduledoc """
  Per-tunnel IPsec diagnostic bundle for a Securepoint over SSH — port of
  the retired `securepoint/ssh.py:fetch_diagnosis`.

  An agent-mode box builds this bundle on the box itself
  (`orbit_agent.py:_diagnose_ipsec`) and relays it. A Securepoint has no
  agent and never will, so the same information has to be gathered over the
  SSH session the swanctl enrichment already uses — which is why the
  Diagnose button did nothing at all on those boxes after the rewrite.

  Section titles deliberately match the agent's, so the UI renders one shape
  regardless of transport.

  Fail-closed like every other Securepoint SSH path: without a configured,
  host-key-pinned SSH access this returns an explanatory section rather than
  connecting unverified — the operator sees WHY instead of an empty panel.
  """

  alias Orbit.Securepoint.SSH

  @sec "@@SEC@@"
  @plain_title "Connection config (swanctl --list-conns)"
  @raw_title "Configured crypto proposals (swanctl --list-conns --raw)"
  # Tunnel ids reach a shell command — but single-quoted at `script/1`
  # (`N='#{name}'`), so `$` is literal there and every later use is `"$N"`
  # (expanded once, never re-parsed). The allow-list therefore includes `$`,
  # which is exactly how Securepoint escapes characters illegal in a
  # strongSwan section id: a space becomes `$20` (`OCV MEH` → `OCV$20MEH`),
  # and that ENCODED form is the id, because `swanctl --ike` wants the section
  # name verbatim. `$` can only ever be followed by hex here, so a literal
  # quote/backtick/paren/semicolon still cannot appear — the guard stays
  # airtight against injection while no longer refusing legit escaped names.
  @safe_name ~r/^[A-Za-z0-9._:$-]{1,128}$/
  @diag_timeout 30_000

  @doc """
  Gather the bundle for one tunnel. Always returns sections — never raises,
  never an empty panel.
  """
  @spec run(Orbit.Instances.Instance.t(), String.t()) :: [map()]
  def run(inst, tunnel_id) do
    cond do
      not Regex.match?(@safe_name, to_string(tunnel_id)) ->
        [section("Diagnostics unavailable", "unsafe tunnel id: #{inspect(tunnel_id)}")]

      true ->
        # config_for/1 answers a bare :error when SSH is off, unconfigured or
        # the host key is unpinned — all three mean the same thing here.
        case SSH.config_for(inst) do
          {:ok, cfg} -> gather(cfg, tunnel_id)
          _ -> [section("SSH required", ssh_hint())]
        end
    end
  end

  defp ssh_hint do
    "Tunnel diagnostics read swanctl and the IPsec log over SSH. Enable SSH " <>
      "enrichment on this instance, with a pinned host key, to use Diagnose."
  end

  defp gather(cfg, tunnel_id) do
    case SSH.connect(cfg) do
      {:ok, conn} ->
        try do
          # The bundle tails syslog and runs a 4s ping — the swanctl-poll
          # budget of 5s truncates it into a timeout.
          case SSH.exec(conn, String.to_charlist(script(tunnel_id)), @diag_timeout) do
            {:ok, out} -> out |> parse_sections() |> scope_sections(tunnel_id)
            {:error, reason} -> [section("Diagnostics unavailable", to_string(reason))]
          end
        after
          :ssh.close(conn)
        end

      {:error, reason} ->
        [section("Diagnostics unavailable", to_string(reason))]
    end
  end

  @doc """
  One shell run emitting `@@SEC@@<title>`-delimited blocks.

  Gathers what the box exposes: the connection config, the raw listing (the
  plain one omits crypto proposals at the strongSwan default), the live SAs,
  the recent charon log with our own vici-poll noise stripped, and a one-shot
  peer ping. `swanctl --list-conns` has no per-connection filter, so both
  config blocks come back whole-box and are sliced afterwards; the SA block
  is already scoped via `--ike`.
  """
  def script(name) do
    """
    N='#{name}'
    echo '#{@sec}#{@plain_title}'
    swanctl --list-conns 2>&1
    echo '#{@sec}#{@raw_title}'
    swanctl --list-conns --raw 2>&1
    echo '#{@sec}Live IKE / CHILD SAs (swanctl --list-sas)'
    swanctl --list-sas --ike "$N" 2>&1
    echo '#{@sec}Recent IPsec log (charon)'
    (echo 'syslog get' | spcli 2>/dev/null) | awk -F'|' 'NR>2 && $3 ~ /charon/ && $0 !~ /\\[CFG\\] vici client/' | tail -n 300
    echo '#{@sec}Peer reachability'
    REMOTE=$(swanctl --list-conns --raw 2>/dev/null | grep -oE 'remote_addrs=\\[[^]]*' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | head -n1)
    [ -z "$REMOTE" ] && REMOTE=$(swanctl --list-sas --ike "$N" --raw 2>/dev/null | grep -oE 'remote-host=[0-9.]+' | head -n1 | cut -d= -f2)
    [ -n "$REMOTE" ] && { echo "ping $REMOTE:"; ping -c 2 -w 4 "$REMOTE" 2>&1; } || echo "no concrete peer IP (remote=%any / responder-only) — nothing to ping"
    """
  end

  @doc false
  def parse_sections(out) when is_binary(out) do
    out
    |> String.split("\n")
    |> Enum.reduce({nil, [], []}, fn line, {title, buf, acc} ->
      if String.starts_with?(line, @sec) do
        acc = flush(title, buf, acc)
        {line |> String.replace_prefix(@sec, "") |> String.trim(), [], acc}
      else
        if title, do: {title, [line | buf], acc}, else: {title, buf, acc}
      end
    end)
    |> then(fn {title, buf, acc} -> flush(title, buf, acc) end)
    |> Enum.reverse()
  end

  defp flush(nil, _buf, acc), do: acc

  defp flush(title, buf, acc) do
    content = buf |> Enum.reverse() |> Enum.join("\n") |> String.trim()
    [section(title, content) | acc]
  end

  # The two whole-box config blocks are sliced down to this tunnel; every
  # other block passes through untouched.
  @doc false
  def scope_sections(sections, tunnel_id) do
    Enum.map(sections, fn
      %{"title" => @plain_title} = s ->
        %{s | "content" => slice_plain(s["content"], tunnel_id)}

      %{"title" => @raw_title} = s ->
        %{s | "content" => slice_raw(s["content"], tunnel_id)}

      s ->
        s
    end)
  end

  # Plain listing: a connection block starts at column 0 with "<name>:" and
  # runs until the next such line.
  @doc false
  def slice_plain(content, name) do
    lines = String.split(to_string(content), "\n")

    case Enum.find_index(lines, &String.starts_with?(&1, "#{name}:")) do
      nil ->
        "(connection not found)"

      start ->
        rest = Enum.drop(lines, start + 1)
        take = Enum.take_while(rest, &(not top_level_conn?(&1)))
        [Enum.at(lines, start) | take] |> Enum.join("\n") |> String.trim()
    end
  end

  defp top_level_conn?(line),
    do: line != "" and not String.starts_with?(line, " ") and String.contains?(line, ":")

  # Raw (vici) listing: one long line per connection, keyed by the name.
  @doc false
  def slice_raw(content, name) do
    content
    |> to_string()
    |> String.split("\n")
    |> Enum.filter(&String.contains?(&1, "#{name}="))
    |> case do
      [] -> "(connection not found)"
      lines -> Enum.join(lines, "\n")
    end
  end

  defp section(title, content), do: %{"title" => title, "content" => content}
end
