defmodule Orbit.Settings.Registry do
  @moduledoc """
  Whitelist of editable settings + value coercion — pure, DB-free. Mirror of
  backend/src/app/settings/registry.py.

  Only keys listed here can be overridden via the settings surface.
  Infra/security settings (database url, master key, trusted proxy hops, …)
  are intentionally absent — they stay env-only. `env` on a def maps the key
  to its `DASH_*` variable for the default; `default` is the fallback when
  the variable is unset.

  Start small: defs are added alongside the features that consume them
  (python has ~40; porting them wholesale before their consumers exist would
  only drift).
  """

  alias Orbit.Settings.Def

  @defs [
    %Def{
      key: "poll_interval_seconds",
      type: :int,
      env: "DASH_POLL_INTERVAL_SECONDS",
      default: "30",
      min: 5,
      max: 86_400
    },
    %Def{
      key: "poll_tick_seconds",
      type: :int,
      env: "DASH_POLL_TICK_SECONDS",
      default: "10",
      min: 1,
      max: 3600
    },
    %Def{
      key: "poll_concurrency",
      type: :int,
      env: "DASH_POLL_CONCURRENCY",
      default: "20",
      min: 1,
      max: 200
    },
    %Def{
      key: "push_interval_seconds",
      type: :int,
      env: "DASH_PUSH_INTERVAL_SECONDS",
      default: "30",
      min: 5,
      max: 86_400
    },
    %Def{
      key: "agent_stale_seconds",
      type: :int,
      env: "DASH_AGENT_STALE_SECONDS",
      default: "120",
      min: 30,
      max: 86_400
    },
    %Def{
      key: "metrics_retention_days",
      type: :int,
      env: "DASH_METRICS_RETENTION_DAYS",
      default: "30",
      min: 1,
      max: 3650
    },
    %Def{
      key: "access_events_retention_days",
      type: :int,
      env: "DASH_ACCESS_EVENTS_RETENTION_DAYS",
      default: "30",
      min: 1,
      max: 365
    },
    %Def{
      key: "access_sessions_retention_days",
      type: :int,
      env: "DASH_ACCESS_SESSIONS_RETENTION_DAYS",
      default: "30",
      min: 1,
      max: 365
    },
    %Def{
      key: "access_stats_retention_days",
      type: :int,
      env: "DASH_ACCESS_STATS_RETENTION_DAYS",
      default: "365",
      min: 7,
      max: 3650
    },
    %Def{
      key: "notify_mattermost_url",
      type: :str,
      env: "DASH_NOTIFY_MATTERMOST_URL",
      default: "",
      is_secret: true
    },
    %Def{
      key: "notify_telegram_token",
      type: :str,
      env: "DASH_NOTIFY_TELEGRAM_TOKEN",
      default: "",
      is_secret: true
    },
    %Def{
      key: "notify_telegram_chat_id",
      type: :str,
      env: "DASH_NOTIFY_TELEGRAM_CHAT_ID",
      default: ""
    },
    %Def{
      key: "notify_mattermost_muted",
      type: :bool,
      env: "DASH_NOTIFY_MATTERMOST_MUTED",
      default: "false"
    },
    %Def{
      key: "notify_telegram_muted",
      type: :bool,
      env: "DASH_NOTIFY_TELEGRAM_MUTED",
      default: "false"
    },
    %Def{
      key: "notify_email_muted",
      type: :bool,
      env: "DASH_NOTIFY_EMAIL_MUTED",
      default: "false"
    },
    %Def{key: "llm_openai_api_key", type: :str, env: "", default: "", is_secret: true},
    %Def{
      key: "llm_openai_base_url",
      type: :str,
      env: "",
      default: "https://api.openai.com/v1"
    },
    %Def{key: "llm_openai_model", type: :str, env: "", default: "gpt-5.5"},
    %Def{key: "llm_anthropic_api_key", type: :str, env: "", default: "", is_secret: true},
    %Def{
      key: "llm_anthropic_base_url",
      type: :str,
      env: "",
      default: "https://api.anthropic.com"
    },
    %Def{key: "llm_anthropic_model", type: :str, env: "", default: "claude-opus-4-8"},
    %Def{key: "llm_openrouter_api_key", type: :str, env: "", default: "", is_secret: true},
    %Def{
      key: "llm_openrouter_base_url",
      type: :str,
      env: "",
      default: "https://openrouter.ai/api/v1"
    },
    %Def{key: "llm_openrouter_model", type: :str, env: "", default: "openai/gpt-5.5"}
  ]

  @editable Map.new(@defs, &{&1.key, &1})

  @spec editable() :: %{String.t() => %Def{}}
  def editable, do: @editable

  @spec fetch(String.t()) :: {:ok, %Def{}} | :error
  def fetch(key), do: Map.fetch(@editable, key)

  @doc """
  Parse + validate a raw string against a setting's type/range/options.
  Returns `{:ok, value}` or `{:error, human_message}` (python parity).
  """
  @spec coerce(%Def{}, String.t()) ::
          {:ok, integer() | boolean() | String.t()} | {:error, String.t()}
  def coerce(%Def{type: :int} = defn, raw) do
    case Integer.parse(String.trim(to_string(raw))) do
      {value, ""} -> check_range(defn, value)
      _ -> {:error, "#{defn.key} must be an integer"}
    end
  end

  def coerce(%Def{type: :bool} = defn, raw) do
    case raw |> to_string() |> String.trim() |> String.downcase() do
      s when s in ~w(1 true yes on) -> {:ok, true}
      s when s in ~w(0 false no off) -> {:ok, false}
      _ -> {:error, "#{defn.key} must be a boolean"}
    end
  end

  def coerce(%Def{type: :str, options: options} = defn, raw) do
    s = to_string(raw)

    if is_nil(options) or s in options do
      {:ok, s}
    else
      {:error, "#{defn.key} must be one of #{Enum.join(options, ", ")}"}
    end
  end

  defp check_range(%Def{min: min, max: max, key: key}, value) do
    cond do
      is_integer(min) and value < min -> {:error, "#{key} must be ≥ #{min}"}
      is_integer(max) and value > max -> {:error, "#{key} must be ≤ #{max}"}
      true -> {:ok, value}
    end
  end
end
