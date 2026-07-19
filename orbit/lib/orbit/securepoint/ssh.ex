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
  Run swanctl over SSH and return the `ipsec` hub section (with SPIs).

  `running` is the service state the caller already knows from the spcgi API —
  swanctl answering at all implies the daemon is up, but the caller stays the
  authority.
  """
  @spec fetch_ipsec_status(%Config{}, boolean()) :: {:ok, map()} | {:error, String.t()}
  def fetch_ipsec_status(%Config{} = cfg, running) when is_boolean(running) do
    with {:ok, conn} <- connect(cfg) do
      try do
        with {:ok, sas} <- exec(conn, ~c"swanctl --list-sas --raw"),
             {:ok, conns} <- exec(conn, ~c"swanctl --list-conns --raw") do
          {:ok, Swanctl.status(sas, conns, running)}
        end
      after
        :ssh.close(conn)
      end
    end
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
