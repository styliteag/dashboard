defmodule Orbit.LLM.Analyze do
  @moduledoc """
  AI log analysis — port of llm/providers.py + llm/analyze.py. Invariant 4:
  ONLY anonymized text ever reaches an external LLM (Orbit.LLM.Anonymize,
  which deliberately keeps RFC1918 IPs), capped at 40k chars. Providers
  are a fixed catalog (openai/anthropic/openrouter); key (secret), base
  url and model come from the shared settings registry per provider.

  Test seams: `opts[:req_plug]`, `opts[:settings]`.
  """

  require Logger

  @max_input_chars 40_000
  # Output budget — on reasoning models this also covers reasoning tokens;
  # too low yields an empty answer (analyze.py lesson).
  @max_tokens 4000
  @timeout_ms 60_000

  @system_prompt "You are a senior network and firewall log analyst for OPNsense/pfSense " <>
                   "systems. Review the log excerpt and report anomalies, errors and " <>
                   "misconfigurations — e.g. ARP flapping or duplicate IPs, interface/driver " <>
                   "errors, failing or restarting services, IPsec tunnel problems, gateway " <>
                   "packet loss, certificate or DNS issues. For each finding give a short " <>
                   "title, a severity (info/warn/critical), the supporting evidence and a " <>
                   "suggested fix. If nothing looks wrong, say so plainly. Be concise and do " <>
                   "not invent issues. Note: IPs/MACs/hostnames may be anonymized."

  @providers [
    %{
      id: "openai",
      label: "OpenAI",
      base_url: "https://api.openai.com/v1",
      model: "gpt-5.5",
      auth: :bearer,
      chat_path: "/chat/completions",
      style: :openai
    },
    %{
      id: "anthropic",
      label: "Anthropic",
      base_url: "https://api.anthropic.com",
      model: "claude-opus-4-8",
      auth: :x_api_key,
      chat_path: "/v1/messages",
      style: :anthropic
    },
    %{
      id: "openrouter",
      label: "OpenRouter",
      base_url: "https://openrouter.ai/api/v1",
      model: "openai/gpt-5.5",
      auth: :bearer,
      chat_path: "/chat/completions",
      style: :openai
    }
  ]

  def providers, do: @providers
  def provider(id), do: Enum.find(@providers, &(&1.id == id))

  @doc "Anonymize + cap the text, call the provider, return the findings."
  def analyze_logs(provider_id, log_text, opts \\ []) do
    settings = Keyword.get(opts, :settings, &setting/1)

    with %{} = p <- provider(provider_id) do
      key = to_string(settings.("llm_#{p.id}_api_key") || "")
      model = presence(settings.("llm_#{p.id}_model")) || p.model

      if key == "" do
        {:error, "No API key configured for #{p.label}"}
      else
        anonymized =
          log_text |> Orbit.LLM.Anonymize.anonymize() |> String.slice(0, @max_input_chars)

        base = presence(settings.("llm_#{p.id}_base_url")) || p.base_url
        {url, headers, body} = build_chat_request(p, base, key, model, anonymized)
        post(p, url, headers, body, model, opts)
      end
    else
      nil -> {:error, "unknown provider"}
    end
  end

  @doc "URL, headers and JSON body for one chat request. Pure."
  def build_chat_request(p, base, key, model, user_text) do
    url = String.trim_trailing(base, "/") <> p.chat_path

    headers =
      case p.auth do
        :bearer -> [{"authorization", "Bearer #{key}"}]
        :x_api_key -> [{"x-api-key", key}, {"anthropic-version", "2023-06-01"}]
      end

    body =
      case p.style do
        :anthropic ->
          %{
            model: model,
            max_tokens: @max_tokens,
            system: @system_prompt,
            messages: [%{role: "user", content: user_text}]
          }

        :openai ->
          # max_completion_tokens: newer OpenAI models reject legacy max_tokens.
          %{
            model: model,
            max_completion_tokens: @max_tokens,
            messages: [
              %{role: "system", content: @system_prompt},
              %{role: "user", content: user_text}
            ]
          }
      end

    {url, headers, body}
  end

  @doc "Extract the assistant text from a provider response. Pure."
  def parse_chat_response(:anthropic, data) do
    (data["content"] || [])
    |> Enum.filter(&(&1["type"] == "text"))
    |> Enum.map_join("", & &1["text"])
    |> String.trim()
  end

  def parse_chat_response(:openai, data) do
    case data["choices"] do
      [first | _] -> String.trim(get_in(first, ["message", "content"]) || "")
      _ -> ""
    end
  end

  defp post(p, url, headers, body, model, opts) do
    base_opts = [
      url: url,
      headers: headers,
      json: body,
      receive_timeout: @timeout_ms,
      retry: false
    ]

    req_opts =
      case Keyword.get(opts, :req_plug, Application.get_env(:orbit, :llm_req_plug)) do
        nil -> base_opts
        plug -> Keyword.put(base_opts, :plug, plug)
      end

    case Req.post(req_opts) do
      {:ok, %{status: 200, body: data}} when is_map(data) ->
        {:ok, %{provider: p.id, model: model, findings: parse_chat_response(p.style, data)}}

      {:ok, %{status: status, body: body}} ->
        {:error, "HTTP #{status}: #{String.slice(inspect(body), 0, 300)}"}

      {:error, error} ->
        Logger.warning("llm.analyze_failed provider=#{p.id} error=#{Exception.message(error)}")
        {:error, "Request failed: #{Exception.message(error)}"}
    end
  end

  defp setting(key) do
    Orbit.Settings.effective(key)
  rescue
    _ -> ""
  end

  defp presence(v) do
    case String.trim(to_string(v || "")) do
      "" -> nil
      s -> s
    end
  end
end
