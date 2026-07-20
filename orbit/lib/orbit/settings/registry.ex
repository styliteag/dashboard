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
      key: "ipsec_event_retention_days",
      type: :int,
      env: "DASH_IPSEC_EVENT_RETENTION_DAYS",
      default: "90",
      min: 1,
      max: 3650
    },
    %Def{
      key: "gui_idle_minutes",
      type: :int,
      env: "DASH_GUI_IDLE_MINUTES",
      default: "15",
      min: 1,
      max: 1440
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
    %Def{key: "llm_openrouter_model", type: :str, env: "", default: "openai/gpt-5.5"},
    %Def{
      key: "notify_email_smtp_host",
      type: :str,
      env: "DASH_NOTIFY_EMAIL_SMTP_HOST",
      default: ""
    },
    %Def{
      key: "notify_email_smtp_port",
      type: :int,
      env: "DASH_NOTIFY_EMAIL_SMTP_PORT",
      default: "587",
      min: 1,
      max: 65_535
    },
    %Def{
      key: "notify_email_security",
      type: :str,
      env: "DASH_NOTIFY_EMAIL_SECURITY",
      default: "starttls",
      options: ~w(starttls ssl none)
    },
    %Def{key: "notify_email_from", type: :str, env: "DASH_NOTIFY_EMAIL_FROM", default: ""},
    %Def{key: "notify_email_to", type: :str, env: "DASH_NOTIFY_EMAIL_TO", default: ""},
    %Def{
      key: "notify_email_username",
      type: :str,
      env: "DASH_NOTIFY_EMAIL_USERNAME",
      default: ""
    },
    %Def{
      key: "notify_email_password",
      type: :str,
      env: "DASH_NOTIFY_EMAIL_PASSWORD",
      default: "",
      is_secret: true
    },
    %Def{
      key: "shell_recording_retention_days",
      type: :int,
      env: "DASH_SHELL_RECORDING_RETENTION_DAYS",
      default: "30",
      min: 1,
      max: 3650
    },
    %Def{
      key: "check_event_retention_days",
      type: :int,
      env: "DASH_CHECK_EVENT_RETENTION_DAYS",
      default: "90",
      min: 1,
      max: 3650
    },
    %Def{
      key: "log_level",
      type: :str,
      env: "DASH_LOG_LEVEL",
      default: "info",
      options: ~w(debug info warning error)
    },
    %Def{
      key: "log_format",
      type: :str,
      env: "DASH_LOG_FORMAT",
      default: "console",
      options: ~w(console json)
    },
    %Def{
      key: "checkmk_blackout",
      type: :bool,
      env: "DASH_CHECKMK_BLACKOUT",
      default: "false"
    },
    %Def{
      key: "checkmk_aggregate",
      type: :bool,
      env: "DASH_CHECKMK_AGGREGATE",
      default: "true"
    }
  ]

  # UI metadata (label / group / help / restart) per key — mirror of the
  # python SettingDef fields, so the Settings page renders friendly labels,
  # grouped tabs, help text and the needs-restart badge. Keys absent here
  # fall back to a humanized label + "Other" group.
  @meta %{
    "poll_interval_seconds" => %{
      group: "Polling",
      label: "Default poll interval",
      help:
        "Default per-instance poll cadence for direct-API devices (seconds).  Instances can override it.",
      restart: false
    },
    "poll_tick_seconds" => %{
      group: "Polling",
      label: "Scheduler tick",
      help:
        "How often the poller wakes to check which instances are due (seconds).  Finest achievable poll resolution.",
      restart: true
    },
    "poll_concurrency" => %{
      group: "Polling",
      label: "Poll concurrency",
      help: "Max instances polled in parallel per tick.",
      restart: false
    },
    "push_interval_seconds" => %{
      group: "Polling",
      label: "Default agent push interval",
      help:
        "Default agent push cadence (seconds), mirrored to the agent.  Instances can override it.",
      restart: false
    },
    "agent_stale_seconds" => %{
      group: "Polling",
      label: "Agent offline floor",
      help:
        "Floor for marking a push-mode instance offline when no push arrives  (seconds). The real threshold scales up with a slower push interval.",
      restart: false
    },
    "metrics_retention_days" => %{
      group: "Retention",
      label: "Metrics retention",
      help: "Raw metrics are pruned after this many days.",
      restart: false
    },
    "ipsec_event_retention_days" => %{
      group: "Retention",
      label: "IPsec event retention",
      help: "IPsec tunnel state-change history kept this many days.",
      restart: false
    },
    "check_event_retention_days" => %{
      group: "Retention",
      label: "Check event retention",
      help: "Service-check state-change history kept this many days.",
      restart: false
    },
    "shell_recording_retention_days" => %{
      group: "Retention",
      label: "Terminal recording retention",
      help:
        "Recorded terminal sessions are deleted after this many days. Only applies when session recording is switched on (DASH_SHELL_RECORD_DIR).",
      restart: false
    },
    "access_events_retention_days" => %{
      group: "Retention",
      label: "Access sample retention",
      help: "Sampled per-request access rows (user IPs) kept this many days.",
      restart: false
    },
    "access_sessions_retention_days" => %{
      group: "Retention",
      label: "Login session retention",
      help: "Ended login sessions kept this many days.",
      restart: false
    },
    "access_stats_retention_days" => %{
      group: "Retention",
      label: "Access aggregate retention",
      help: "Hourly per-principal request counters kept this many days.",
      restart: false
    },
    "gui_idle_minutes" => %{
      group: "GUI proxy",
      label: "GUI proxy idle close",
      help:
        "Close an idle firewall-GUI tunnel after this many minutes with no active connections.",
      restart: false
    },
    "log_level" => %{
      group: "Service",
      label: "Log level",
      help: "Backend log verbosity. Applies immediately (no restart needed).",
      restart: false
    },
    "log_format" => %{
      group: "Service",
      label: "Log format",
      help:
        "Backend log output: human-readable console lines or JSON lines. Applies immediately (no restart needed).",
      restart: false
    },
    "notify_mattermost_url" => %{
      group: "Mattermost",
      label: "Webhook URL",
      help: "Incoming-webhook URL of a Mattermost channel. Stored encrypted.",
      restart: false
    },
    "notify_telegram_token" => %{
      group: "Telegram",
      label: "Bot token",
      help:
        "Telegram bot API token. Stored encrypted. Telegram is used only when  both token and chat ID are set.",
      restart: false
    },
    "notify_telegram_chat_id" => %{
      group: "Telegram",
      label: "Chat ID",
      help: "Target chat/channel ID the bot posts to.",
      restart: false
    },
    "notify_email_smtp_host" => %{
      group: "Email",
      label: "SMTP host",
      help: "SMTP server hostname. Email is used only when host, from and to are all set.",
      restart: false
    },
    "notify_email_smtp_port" => %{
      group: "Email",
      label: "SMTP port",
      help: "SMTP server port (587 for STARTTLS, 465 for implicit TLS, 25 for none).",
      restart: false
    },
    "notify_email_security" => %{
      group: "Email",
      label: "Transport security",
      help: "STARTTLS (587), implicit TLS/SSL (465) or none (plaintext, 25).",
      restart: false
    },
    "notify_email_from" => %{
      group: "Email",
      label: "From address",
      help: "Envelope/From sender address for alert emails.",
      restart: false
    },
    "notify_email_to" => %{
      group: "Email",
      label: "Recipients",
      help: "One or more recipient addresses, comma- or space-separated.",
      restart: false
    },
    "notify_email_username" => %{
      group: "Email",
      label: "SMTP username",
      help: "SMTP auth username. Leave empty for an unauthenticated relay.",
      restart: false
    },
    "notify_email_password" => %{
      group: "Email",
      label: "SMTP password",
      help: "SMTP auth password. Stored encrypted.",
      restart: false
    },
    "notify_mattermost_muted" => %{
      group: "Maintenance",
      label: "Mute Mattermost alerts",
      help:
        "Pause Mattermost alert delivery. Real alerts are skipped while muted;  an explicit Send test still fires. Toggle off to resume.",
      restart: false
    },
    "notify_telegram_muted" => %{
      group: "Maintenance",
      label: "Mute Telegram alerts",
      help:
        "Pause Telegram alert delivery. Real alerts are skipped while muted;  an explicit Send test still fires. Toggle off to resume.",
      restart: false
    },
    "notify_email_muted" => %{
      group: "Maintenance",
      label: "Mute Email alerts",
      help:
        "Pause Email alert delivery. Real alerts are skipped while muted;  an explicit Send test still fires. Toggle off to resume.",
      restart: false
    },
    "checkmk_blackout" => %{
      group: "Maintenance",
      label: "Checkmk blackout",
      help:
        "Return an empty Checkmk export so every service goes stale/gone. Use  during maintenance to suppress Checkmk alerting. Toggle off to resume.",
      restart: false
    },
    "checkmk_aggregate" => %{
      group: "Checkmk",
      label: "Aggregate services",
      help:
        "Collapse high-fan-out checks (certificates, IPsec tunnels, services,  interfaces, gateways, connectivity, disks) into one aggregate service per  category — the worst member state wins and the offenders are named in the  summary. Cuts a box from hundreds of Checkmk services to a handful. Turning  this off (or on) changes which services Checkmk discovers.",
      restart: false
    },
    "llm_openai_api_key" => %{
      group: "OpenAI",
      label: "OpenAI API key",
      help: "API key for OpenAI-compatible chat completions.",
      restart: false
    },
    "llm_openai_base_url" => %{
      group: "OpenAI",
      label: "OpenAI base URL",
      help: "Override the OpenAI API base URL (self-hosted / proxy).",
      restart: false
    },
    "llm_openai_model" => %{
      group: "OpenAI",
      label: "OpenAI model",
      help: "Model id used for log analysis.",
      restart: false
    },
    "llm_anthropic_api_key" => %{
      group: "Anthropic",
      label: "Anthropic API key",
      help: "API key for Anthropic (Claude) messages.",
      restart: false
    },
    "llm_anthropic_base_url" => %{
      group: "Anthropic",
      label: "Anthropic base URL",
      help: "Override the Anthropic API base URL.",
      restart: false
    },
    "llm_anthropic_model" => %{
      group: "Anthropic",
      label: "Anthropic model",
      help: "Model id used for log analysis.",
      restart: false
    },
    "llm_openrouter_api_key" => %{
      group: "OpenRouter",
      label: "OpenRouter API key",
      help: "API key for OpenRouter.",
      restart: false
    },
    "llm_openrouter_base_url" => %{
      group: "OpenRouter",
      label: "OpenRouter base URL",
      help: "Override the OpenRouter API base URL.",
      restart: false
    },
    "llm_openrouter_model" => %{
      group: "OpenRouter",
      label: "OpenRouter model",
      help: "Model id used for log analysis.",
      restart: false
    }
  }

  @doc "UI metadata for a key: %{group, label, help, restart}."
  def meta(key) do
    Map.get(@meta, key, %{
      group: "Other",
      label: key |> String.replace("_", " ") |> String.capitalize(),
      help: "",
      restart: false
    })
  end

  @editable Map.new(@defs, &{&1.key, &1})

  @spec editable() :: %{String.t() => %Def{}}
  def editable, do: @editable

  # The @defs list order is curated (python registry parity: the common
  # settings lead each group) — the UI sorts rows by it, not alphabetically.
  @ordered_keys Enum.map(@defs, & &1.key)

  @doc "Definition order of all keys — the settings page's row order."
  def ordered_keys, do: @ordered_keys

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
