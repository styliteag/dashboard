defmodule Orbit.Securepoint.SSH do
  @moduledoc """
  SSH transport for Securepoint: run `swanctl --raw` on the box and parse it.

  Port of the deleted `backend/src/app/securepoint/ssh.py`. The dashboard
  authenticates with one ed25519 key per instance (`just gen-ssh-key`, private
  half stored Fernet-encrypted in `instances.ssh_key_enc`, public half installed
  on the box — see `docs/securepoint-ssh.md`). This is what gives the pull path
  the IKE cookies, ESP SPIs and byte counters that the spcgi API never exposes,
  i.e. the data needed to pair tunnel ends across NAT.

  ## Host-key handling is trust-on-first-use, FAIL-CLOSED

  A command-running connection refuses to proceed unless a pinned host key is
  present AND matches the server. `probe_host_key/1` is the only path that
  connects unpinned, and only to capture the key for storage. Until a key is
  pinned, callers fall back to the spcgi API.

  Do not "simplify" this into accepting any host key: without verification an
  on-path attacker impersonates the box and feeds fabricated swanctl output,
  which the dashboard would render as tunnel state and alert on.

  Erlang's `:ssh` (no external dependency) does the work. It must stay listed in
  `extra_applications` in mix.exs — Elixir prunes the code path to the declared
  applications, so without it `:ssh` is missing from `mix run` AND the release.
  """

  alias Orbit.Securepoint.Swanctl

  @connect_timeout 8_000
  @cmd_timeout 5_000

  defmodule Config do
    @moduledoc "Per-instance SSH access (private key already decrypted)."
    @enforce_keys [:host, :port, :user, :private_key]
    defstruct [:host, :port, :user, :private_key, host_key: nil]
  end

  defmodule KeyCb do
    @moduledoc """
    `:ssh_client_key_api` callback: supplies the client key and decides the host
    key. Erlang has no "give me the server key after the handshake" hook, so the
    comparison happens here — which is also the only place it CAN be
    fail-closed, because returning false aborts before any channel opens.
    """
    @behaviour :ssh_client_key_api

    @impl true
    def user_key(_algo, opts) do
      {:ok, Keyword.fetch!(opts[:key_cb_private], :priv_key)}
    end

    @impl true
    def is_host_key(key, _host, _port, _algo, opts) do
      priv = opts[:key_cb_private]

      case Keyword.get(priv, :pinned) do
        nil ->
          # TOFU capture only — reached via probe_host_key/1, never while
          # running a command.
          send(
            Keyword.fetch!(priv, :reply_to),
            {:host_key, Orbit.Securepoint.SSH.encode_key(key)}
          )

          true

        pinned ->
          Orbit.Securepoint.SSH.same_key?(Orbit.Securepoint.SSH.encode_key(key), pinned)
      end
    end

    @impl true
    def add_host_key(_host, _port, _key, _opts), do: :ok
  end

  # -- public ---------------------------------------------------------------

  @doc """
  Build the per-instance SSH config, decrypting the stored key.

  One source for both callers — the poller's swanctl enrichment and the
  interactive terminal — so they can never drift on which host, port, user or
  key is used. `:error` when the instance is not SSH-configured; the caller
  decides whether that is "skip the enrichment" or "no shell here".
  """
  @spec config_for(struct()) :: {:ok, %Config{}} | :error
  def config_for(inst) do
    with key when is_binary(key) and key != "" <- decrypted_key(inst),
         host when is_binary(host) and host != "" <- ssh_host(inst) do
      {:ok,
       %Config{
         host: host,
         port: inst.ssh_port || 22,
         user: inst.ssh_user || "root",
         private_key: key,
         host_key: inst.ssh_host_key
       }}
    else
      _ -> :error
    end
  end

  defp decrypted_key(%{ssh_key_enc: nil}), do: nil

  defp decrypted_key(%{ssh_key_enc: enc}) do
    case Orbit.Crypto.decrypt(enc) do
      {:ok, key} -> key
      _ -> nil
    end
  end

  # SSH targets the box itself, not its API URL — take the host out of base_url.
  defp ssh_host(inst) do
    case inst |> Orbit.Instances.Instance.primary_base_url() |> URI.parse() do
      %URI{host: h} when is_binary(h) and h != "" -> h
      _ -> nil
    end
  end

  @doc """
  Run swanctl over SSH and return the `ipsec` hub section (with SPIs).

  `running` is the service state the caller already knows from the spcgi API —
  swanctl answering at all implies the daemon is up, but the caller stays the
  authority.
  """
  @spec fetch_ipsec_status(%Config{}, boolean()) :: {:ok, map()} | {:error, String.t()}
  def fetch_ipsec_status(%Config{} = cfg, running) when is_boolean(running) do
    with_connection(cfg, &ipsec_status(&1, running))
  end

  @doc """
  Open one connection, run `fun.(conn)`, close it again.

  Everything a single poll needs from the box should go through ONE call: the
  swanctl dump and every ping monitor together. Two handshakes per poll against
  a remote appliance is pure waste, and the poll runs on an interval.
  """
  @spec with_connection(%Config{}, (term() -> result)) :: result | {:error, String.t()}
        when result: term()
  def with_connection(%Config{} = cfg, fun) when is_function(fun, 1) do
    with {:ok, conn} <- connect(cfg) do
      try do
        fun.(conn)
      after
        :ssh.close(conn)
      end
    end
  end

  @doc "The `ipsec` section over an ALREADY open connection."
  def ipsec_status(conn, running) do
    with {:ok, sas} <- exec(conn, ~c"swanctl --list-sas --raw"),
         {:ok, conns} <- exec(conn, ~c"swanctl --list-conns --raw") do
      {:ok, Swanctl.status(sas, conns, running)}
    end
  end

  @doc """
  Open a host-key-verified connection plus an interactive login PTY.

  Returns `{:ok, conn, channel}`. The CALLER becomes the owner: `:ssh` delivers
  channel messages to the process that opened it, so the WebSocket process opens
  this itself and receives PTY output directly as `{:ssh_cm, conn, …}`.

  The caller MUST close the channel and then the connection when the session
  ends — otherwise a root shell lingers on the box. `close_interactive/2` does
  both in the right order.

  Fail-closed like everything else here: an unpinned or mismatched host key
  refuses before any channel is opened.
  """
  @spec open_interactive(%Config{}, pos_integer(), pos_integer()) ::
          {:ok, term(), term()} | {:error, String.t()}
  def open_interactive(%Config{} = cfg, rows, cols) do
    with {:ok, conn} <- connect(cfg) do
      with {:ok, chan} <- session_channel(conn),
           :ok <- alloc_pty(conn, chan, rows, cols),
           :ok <- start_shell(conn, chan) do
        {:ok, conn, chan}
      else
        {:error, reason} ->
          :ssh.close(conn)
          {:error, "open interactive shell failed: #{describe(reason)}"}
      end
    end
  end

  @doc "Close the PTY channel, then the connection. Safe to call twice."
  def close_interactive(conn, chan) do
    if chan, do: :ssh_connection.close(conn, chan)
    :ssh.close(conn)
    :ok
  rescue
    _ -> :ok
  end

  @doc "Tell the box the terminal was resized."
  def resize(conn, chan, rows, cols) do
    :ssh_connection.window_change(conn, chan, cols, rows)
    :ok
  rescue
    _ -> :ok
  end

  @doc "Forward keystrokes to the PTY."
  def send_data(conn, chan, data) do
    :ssh_connection.send(conn, chan, data, @cmd_timeout)
  rescue
    _ -> {:error, :closed}
  end

  defp session_channel(conn) do
    case :ssh_connection.session_channel(conn, @cmd_timeout) do
      {:ok, chan} -> {:ok, chan}
      {:error, reason} -> {:error, reason}
    end
  end

  defp alloc_pty(conn, chan, rows, cols) do
    case :ssh_connection.ptty_alloc(conn, chan, [
           {:term, ~c"xterm-256color"},
           {:width, cols},
           {:height, rows}
         ]) do
      :success -> :ok
      other -> {:error, other}
    end
  end

  defp start_shell(conn, chan) do
    case :ssh_connection.shell(conn, chan) do
      :ok -> :ok
      other -> {:error, other}
    end
  end

  @doc """
  Run one ping ON the box and classify it — the agent's `_ping_once` over SSH.

  This is how an agent-less appliance gets IPsec Phase-2 and connectivity
  monitors at all: the probe has to originate ON the box (through the tunnel,
  from the right source address), which is exactly what an agent would do and
  what the dashboard cannot do from outside.

  Three outcomes, and the middle one matters:

    ok    — replies came back
    fail  — no reply: the target is down or the tunnel is not passing traffic
    error — the probe never RAN (unassignable source, unresolvable host). That
            is a misconfiguration, not an outage, and must not read as one.

  The discriminator is the summary line: no `% packet loss` at all means ping
  refused to start. Verified on a live UTM — a bogus source prints
  "can't set multicast source interface" and no summary.
  """
  @spec ping(term(), String.t() | nil, String.t() | nil, pos_integer()) :: map()
  def ping(_conn, _source, dest, _count) when dest in [nil, ""] do
    %{"ping_state" => "error", "ping_loss_pct" => nil, "ping_rtt_ms" => nil}
  end

  def ping(conn, source, dest, count) do
    count = max(count || 3, 1)
    # Pace 0.3s apart so a healthy target answers well inside the deadline.
    # -W is the busybox spelling and iputils accepts it too (both checked on a
    # live box); -I binds the source on either.
    src = if present(source), do: " -I #{shell_arg(source)}", else: ""
    cmd = "ping -n -i 0.3 -c #{count} -W #{max(count, 2)}#{src} #{shell_arg(dest)} 2>&1"

    case exec(conn, String.to_charlist(cmd)) do
      {:ok, out} -> classify(out)
      {:error, _} -> %{"ping_state" => "error", "ping_loss_pct" => nil, "ping_rtt_ms" => nil}
    end
  end

  defp classify(out) do
    case Regex.run(~r/([\d.]+)%\s*packet loss/, out) do
      [_, loss_s] ->
        loss = String.to_float(ensure_float(loss_s))

        %{
          "ping_state" => if(loss < 100, do: "ok", else: "fail"),
          "ping_loss_pct" => loss,
          "ping_rtt_ms" => avg_rtt(out)
        }

      _ ->
        # No summary line at all → the probe never ran.
        %{"ping_state" => "error", "ping_loss_pct" => nil, "ping_rtt_ms" => nil}
    end
  end

  defp avg_rtt(out) do
    case Regex.run(~r/=\s*[\d.]+\/([\d.]+)\//, out) do
      [_, avg] -> String.to_float(ensure_float(avg))
      _ -> nil
    end
  end

  defp ensure_float(s), do: if(String.contains?(s, "."), do: s, else: s <> ".0")

  defp present(v), do: is_binary(v) and String.trim(v) != ""

  # Monitor sources/destinations are operator-entered. Refuse anything that is
  # not a plain host/IP token rather than interpolating it into a shell command.
  defp shell_arg(v) do
    v = String.trim(to_string(v))
    if Regex.match?(~r/^[A-Za-z0-9._:\-]+$/, v), do: v, else: "--"
  end

  @doc """
  Prove the configured access actually works — the edit form's "Test" button.

  Deliberately exercises the REAL enrichment path rather than just opening a
  socket: it logs in, reports which account it landed as, and then runs the same
  swanctl dumps the poller runs and parses them. "SSH connects" and "swanctl
  answers" are different failures — a box can accept the key while strongSwan is
  absent or the account cannot read it — and the operator needs to know which.
  """
  @spec test_access(%Config{}) :: {:ok, String.t()} | {:error, String.t()}
  def test_access(%Config{} = cfg) do
    with_connection(cfg, fn conn ->
      who =
        case exec(conn, ~c"id -un") do
          {:ok, out} -> String.trim(out)
          _ -> cfg.user
        end

      case ipsec_status(conn, true) do
        {:ok, %{"tunnels" => tunnels}} ->
          {:ok,
           "connected as #{who}@#{cfg.host}:#{cfg.port} — swanctl answered, " <>
             "#{length(tunnels)} tunnel(s) configured"}

        _ ->
          {:error,
           "connected as #{who}@#{cfg.host}:#{cfg.port}, but swanctl did not answer — " <>
             "IPsec enrichment will fall back to the API"}
      end
    end)
  end

  @doc """
  Connect once WITHOUT a pinned key and return the box's host key for storage.

  The only unpinned path in this module (trust on first use). Everything else
  refuses to run unverified.
  """
  @spec probe_host_key(%Config{}) :: {:ok, String.t()} | {:error, String.t()}
  def probe_host_key(%Config{} = cfg) do
    with {:ok, conn} <- connect(%{cfg | host_key: nil}, require_host_key: false) do
      :ssh.close(conn)

      receive do
        {:host_key, line} -> {:ok, line}
      after
        0 -> {:error, "connected but the server host key was never offered"}
      end
    end
  end

  @doc false
  def connect(%Config{} = cfg, opts \\ []) do
    if Keyword.get(opts, :require_host_key, true) and blank?(cfg.host_key) do
      {:error,
       "SSH host key not pinned — refusing to connect unverified " <>
         "(enrichment falls back to the spcgi API until the key is captured)"}
    else
      do_connect(cfg)
    end
  end

  # The stored line names its algorithm; PREFER that family so the server
  # presents the key we can actually verify. A box commonly offers several host
  # keys and Erlang would otherwise negotiate by its own order — pinned RSA vs
  # negotiated ECDSA is a guaranteed mismatch and a silent fail-closed refusal.
  #
  # It must be `modify_algorithms [prepend:]`, and both alternatives were
  # measured against a live box:
  #   pref_public_key_algs            -> the USER-auth key list. Leaves the host
  #                                      key untouched AND breaks publickey auth
  #                                      by excluding our ed25519 client key.
  #   preferred_algorithms public_key -> REPLACES the list. Gets the right host
  #                                      key, but drops ed25519 with it, so auth
  #                                      fails.
  #   modify_algorithms prepend       -> reorders only. Right host key, auth
  #                                      still works. This one.
  # RSA additionally accepts the SHA-2 signature algorithms: same key material,
  # newer signing.
  defp host_key_algs(nil), do: []

  defp host_key_algs(line) when is_binary(line) do
    case line |> String.trim() |> String.split(~r/\s+/) |> List.first() do
      "ssh-rsa" ->
        [
          modify_algorithms: [
            prepend: [public_key: [:"rsa-sha2-512", :"rsa-sha2-256", :"ssh-rsa"]]
          ]
        ]

      "ssh-ed25519" ->
        [modify_algorithms: [prepend: [public_key: [:"ssh-ed25519"]]]]

      "ecdsa-sha2-nistp256" ->
        [modify_algorithms: [prepend: [public_key: [:"ecdsa-sha2-nistp256"]]]]

      "ecdsa-sha2-nistp384" ->
        [modify_algorithms: [prepend: [public_key: [:"ecdsa-sha2-nistp384"]]]]

      "ecdsa-sha2-nistp521" ->
        [modify_algorithms: [prepend: [public_key: [:"ecdsa-sha2-nistp521"]]]]

      _ ->
        []
    end
  end

  defp host_key_algs(_), do: []

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(v) when is_binary(v), do: String.trim(v) == ""
  defp blank?(_), do: false

  defp do_connect(%Config{} = cfg) do
    with {:ok, priv_key} <- decode_private_key(cfg.private_key) do
      key_cb_private =
        [priv_key: priv_key, reply_to: self()] ++
          if(cfg.host_key, do: [pinned: cfg.host_key], else: [])

      opts =
        [
          user: String.to_charlist(cfg.user || "root"),
          auth_methods: ~c"publickey",
          key_cb: {KeyCb, key_cb_private}
          # Pin the HOST-KEY ALGORITHM to the one we stored, or the comparison is
          # a coin toss: a box commonly offers several host keys (RSA + ECDSA +
          # ed25519) and Erlang would negotiate by its own preference. Pinning an
          # RSA key while Erlang picks ECDSA yields a guaranteed blob mismatch and
          # a fail-closed refusal — the enrichment then never runs, silently.
          # Observed on a live box: pinned ssh-rsa, negotiated ecdsa-sha2-nistp256.
        ] ++
          host_key_algs(cfg.host_key) ++
          [
            silently_accept_hosts: false,
            user_interaction: false,
            save_accepted_host: false,
            quiet_mode: true,
            connect_timeout: @connect_timeout
          ]

      case :ssh.connect(String.to_charlist(cfg.host), cfg.port || 22, opts, @connect_timeout) do
        {:ok, conn} ->
          {:ok, conn}

        {:error, reason} ->
          {:error, "SSH connect #{cfg.user}@#{cfg.host}:#{cfg.port} failed: #{describe(reason)}"}
      end
    end
  end

  @doc false
  def exec(conn, command) do
    case :ssh_connection.session_channel(conn, @cmd_timeout) do
      {:ok, chan} ->
        :ssh_connection.exec(conn, chan, command, @cmd_timeout)
        collect(conn, chan, [])

      {:error, reason} ->
        {:error, "swanctl over SSH failed: #{describe(reason)}"}
    end
  end

  defp collect(conn, chan, acc) do
    receive do
      # type 0 = stdout; 1 = stderr, which swanctl uses for warnings we ignore.
      {:ssh_cm, ^conn, {:data, ^chan, 0, data}} -> collect(conn, chan, [data | acc])
      {:ssh_cm, ^conn, {:data, ^chan, _type, _data}} -> collect(conn, chan, acc)
      {:ssh_cm, ^conn, {:eof, ^chan}} -> collect(conn, chan, acc)
      {:ssh_cm, ^conn, {:exit_status, ^chan, _status}} -> collect(conn, chan, acc)
      {:ssh_cm, ^conn, {:closed, ^chan}} -> {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}
      {:ssh_cm, ^conn, _other} -> collect(conn, chan, acc)
    after
      @cmd_timeout ->
        :ssh_connection.close(conn, chan)
        {:error, "swanctl over SSH timed out after #{@cmd_timeout}ms"}
    end
  end

  @doc """
  The base64 blob of an `ssh-ed25519 AAAA… [comment]` line.

  Comparison is on the identity part only: the comment is free text the box may
  rewrite, and the algorithm prefix is implied by the blob.
  """
  def key_blob(line) when is_binary(line) do
    case String.split(String.trim(line), ~r/\s+/) do
      [_algo, blob | _] -> blob
      _ -> String.trim(line)
    end
  end

  @doc false
  def same_key?(a, b), do: key_blob(a) == key_blob(b)

  @doc false
  def encode_key(key) do
    [{key, []}] |> :ssh_file.encode(:openssh_key) |> to_string() |> String.trim()
  rescue
    _ -> ""
  end

  @doc false
  def decode_private_key(pem) when is_binary(pem) do
    if String.trim(pem) == "" do
      {:error, "no SSH private key configured for this instance"}
    else
      case :ssh_file.decode(pem, :openssh_key_v1) do
        [{key, _attrs} | _] -> {:ok, key}
        _ -> {:error, "bad SSH private key: could not decode"}
      end
    end
  rescue
    e -> {:error, "bad SSH private key: #{Exception.message(e)}"}
  end

  def decode_private_key(_), do: {:error, "no SSH private key configured for this instance"}

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason) when is_list(reason), do: to_string(reason)
  defp describe(reason), do: inspect(reason)
end
