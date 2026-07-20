defmodule Orbit.Agent.Package do
  @moduledoc """
  The agent code this container serves for self-update — port of the
  `_agent_update_params` half of update.py. The dashboard only RELAYS the
  offline-produced Ed25519 signature (orbit_agent.py.sig); it never holds the
  signing key. The fleet-bricking verification (signature, anti-rollback,
  exit-42 respawn, probation) lives in orbit_agent.py and is untouched.

  Agent files are mounted read-only at AGENT_DIR (/app/agent), same as the
  python backend.
  """

  @version_re ~r/^__version__\s*=\s*["']([^"']+)["']/m

  @doc "AGENT_DIR from the env (defaults to /app/agent)."
  def agent_dir, do: System.get_env("AGENT_DIR", "/app/agent")

  @doc "Parse __version__ from the served agent script, or nil."
  @spec served_version() :: String.t() | nil
  def served_version do
    with {:ok, text} <- File.read(Path.join(agent_dir(), "orbit_agent.py")),
         [_, version] <- Regex.run(@version_re, text) do
      version
    else
      _ -> nil
    end
  end

  @doc """
  Build the agent.update command params (version, sha256, base64 code, the
  relayed signature), or `{:error, :unavailable}` if the script is missing.
  """
  @spec update_params() :: {:ok, map()} | {:error, :unavailable}
  def update_params do
    case File.read(Path.join(agent_dir(), "orbit_agent.py")) do
      {:ok, code} ->
        signature =
          case File.read(Path.join(agent_dir(), "orbit_agent.py.sig")) do
            {:ok, sig} -> String.trim(sig)
            _ -> ""
          end

        {:ok,
         %{
           "version" => served_version() || "unknown",
           "sha256" => :crypto.hash(:sha256, code) |> Base.encode16(case: :lower),
           "code" => Base.encode64(code),
           "signature" => signature
         }}

      {:error, _} ->
        {:error, :unavailable}
    end
  end

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
