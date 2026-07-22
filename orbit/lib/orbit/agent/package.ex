defmodule Orbit.Agent.Package do
  @moduledoc """
  The agent code this container serves for self-update — port of the
  `_agent_update_params` half of update.py. The dashboard only RELAYS the
  offline-produced Ed25519 signature (`<file>.sig`); it never holds the
  signing key. The fleet-bricking verification (signature, anti-rollback,
  exit-42 respawn, probation) lives in the agent and is untouched.

  Since the agent split (§28) there are TWO single-file agent lines, chosen
  by the instance's device type via `line_for/1`:

  - `:firewall` — `orbit_agent.py` (OPNsense/pfSense, FreeBSD). Keeps its
    historical name so the deployed firewall fleet's self-update path is
    byte-for-byte unchanged.
  - `:linux` — `orbit_agent_linux.py` (generic Linux nodes, §25). Served
    to `device_type == "linux"` instances; on the box it still lands at
    /usr/local/orbit-agent/orbit_agent.py, so supervisor + systemd unit
    stay untouched.

  Agent files are mounted read-only at AGENT_DIR (/app/agent), same as the
  python backend.
  """

  @version_re ~r/^__version__\s*=\s*["']([^"']+)["']/m

  @agent_files %{
    firewall: "orbit_agent.py",
    linux: "orbit_agent_linux.py"
  }

  @doc "The two agent lines."
  def lines, do: Map.keys(@agent_files)

  @doc """
  Which agent line an instance's device_type gets. Everything that is not a
  Linux node is the firewall line — Securepoint is pull-only and never asks.
  """
  @spec line_for(String.t() | nil) :: :firewall | :linux
  def line_for("linux"), do: :linux
  def line_for(_other), do: :firewall

  @doc "AGENT_DIR from the env (defaults to /app/agent)."
  def agent_dir, do: System.get_env("AGENT_DIR", "/app/agent")

  @doc "Parse __version__ from the served agent script of a line, or nil."
  @spec served_version(:firewall | :linux) :: String.t() | nil
  def served_version(line \\ :firewall) do
    with {:ok, text} <- File.read(agent_path(line)),
         [_, version] <- Regex.run(@version_re, text) do
      version
    else
      _ -> nil
    end
  end

  @doc "Served version per line: `%{firewall: v | nil, linux: v | nil}`."
  @spec served_versions() :: %{firewall: String.t() | nil, linux: String.t() | nil}
  def served_versions do
    Map.new(lines(), &{&1, served_version(&1)})
  end

  @doc """
  Build the agent.update command params (version, sha256, base64 code, the
  relayed signature) for a line, or `{:error, :unavailable}` if the script
  is missing.
  """
  @spec update_params(:firewall | :linux) :: {:ok, map()} | {:error, :unavailable}
  def update_params(line \\ :firewall) do
    case File.read(agent_path(line)) do
      {:ok, code} ->
        signature =
          case File.read(agent_path(line) <> ".sig") do
            {:ok, sig} -> String.trim(sig)
            _ -> ""
          end

        {:ok,
         %{
           "version" => served_version(line) || "unknown",
           "sha256" => :crypto.hash(:sha256, code) |> Base.encode16(case: :lower),
           "code" => Base.encode64(code),
           "signature" => signature
         }}

      {:error, _} ->
        {:error, :unavailable}
    end
  end

  defp agent_path(line), do: Path.join(agent_dir(), Map.fetch!(@agent_files, line))

  @doc """
  sha256 of the vendored Checkmk agent script we serve, or nil when it is
  missing. Compared against the `checkmk_sha256` a Linux node reports in its
  hello frame to decide whether it needs a refresh.
  """
  @spec checkmk_sha256() :: String.t() | nil
  def checkmk_sha256 do
    case File.read(checkmk_path()) do
      {:ok, code} -> :crypto.hash(:sha256, code) |> Base.encode16(case: :lower)
      _ -> nil
    end
  end

  @doc """
  Params for the agent's `checkmk.update` command — same trust chain as an
  agent self-update: sha256 plus the offline Ed25519 signature, which the
  agent verifies against its baked-in public key before writing anything.
  """
  @spec checkmk_update_params() :: {:ok, map()} | {:error, :unavailable}
  def checkmk_update_params do
    case File.read(checkmk_path()) do
      {:ok, code} ->
        signature =
          case File.read(checkmk_path() <> ".sig") do
            {:ok, sig} -> String.trim(sig)
            _ -> ""
          end

        {:ok,
         %{
           "sha256" => :crypto.hash(:sha256, code) |> Base.encode16(case: :lower),
           "code" => Base.encode64(code),
           "signature" => signature
         }}

      {:error, _} ->
        {:error, :unavailable}
    end
  end

  defp checkmk_path, do: Path.join([agent_dir(), "vendor", "check_mk_agent.linux"])
end
