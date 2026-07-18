defmodule Orbit.Firewall do
  @moduledoc """
  OPNsense firewall-rules management — port of firewall_rules/routes.py.
  Talks the OPNsense filter MVC API either through the agent (`http.relay`
  command, push/relay instances) or the direct OPNsense API client. Only
  OPNsense device types are supported (device caps `firewall_rules`).

  search/toggle/delete/apply are the operational core; add/set relay the
  full rule payload straight through. Rule rows are normalised to a flat
  shape (normalize_rule) since OPNsense returns select fields as nested
  option objects. Every write audits `firewall.rule.*`.

  Test seam: `opts[:relay]` (a fn (method, path, body) -> {:ok, map} |
  {:error, msg}) replaces the transport.
  """

  alias Orbit.Hub
  alias Orbit.Instances.Instance
  alias Orbit.Poller.OpnsenseClient

  @relay_timeout_ms 30_000

  @doc "Supported only for OPNsense device types (firewall_rules capability)."
  def supported?(%Instance{device_type: dt}), do: dt in ["opnsense"]

  @doc "Search rules on an interface → {:ok, %{rows, total}} | {:error, msg}."
  def search_rules(inst, opts \\ []) do
    interface = Keyword.get(opts, :interface)
    search = Keyword.get(opts, :search, "")

    params =
      if interface, do: "?interface=#{URI.encode(interface)}&show_all=1", else: "?show_all=1"

    body = %{"current" => 1, "rowCount" => 500, "sort" => %{}, "searchPhrase" => search}

    case relay(inst, "POST", "/api/firewall/filter/search_rule#{params}", body, opts) do
      {:ok, data} ->
        rows = for row <- data["rows"] || [], is_map(row), do: normalize_rule(row)
        {:ok, %{rows: rows, total: to_int(data["total"], length(rows))}}

      {:error, msg} ->
        {:error, msg}
    end
  end

  @doc "Enable/disable a rule (toggle). action → firewall.rule.toggle."
  def toggle_rule(inst, uuid, enabled?, opts \\ []) do
    suffix = if enabled?, do: "/1", else: "/0"
    write(inst, "/api/firewall/filter/toggle_rule/#{uuid}#{suffix}", "firewall.rule.toggle", opts)
  end

  @doc "Delete a rule. action → firewall.rule.delete."
  def delete_rule(inst, uuid, opts \\ []) do
    write(inst, "/api/firewall/filter/del_rule/#{uuid}", "firewall.rule.delete", opts)
  end

  @doc "Apply staged changes. action → firewall.rule.apply."
  def apply(inst, opts \\ []) do
    write(inst, "/api/firewall/filter/apply", "firewall.rule.apply", opts)
  end

  @doc "Get one rule's full field set (for the editor)."
  def get_rule(inst, uuid, opts \\ []) do
    case relay(inst, "GET", "/api/firewall/filter/get_rule/#{uuid}", nil, opts) do
      {:ok, data} -> {:ok, data["rule"] || %{}}
      err -> err
    end
  end

  @doc "Create/update a rule from a field map (add when uuid nil)."
  def save_rule(inst, uuid, fields, opts \\ []) do
    {path, action} =
      if uuid,
        do: {"/api/firewall/filter/set_rule/#{uuid}", "firewall.rule.set"},
        else: {"/api/firewall/filter/add_rule", "firewall.rule.add"}

    write(inst, path, action, Keyword.put(opts, :body, %{"rule" => fields}))
  end

  # -- transport ------------------------------------------------------------

  defp write(inst, path, action, opts) do
    body = Keyword.get(opts, :body)

    case relay(inst, "POST", path, body, opts) do
      {:ok, data} ->
        ok = action_ok?(data)
        audit(opts, inst, action, if(ok, do: "ok", else: "error"), data)
        if ok, do: {:ok, data}, else: {:error, upstream_msg(data)}

      {:error, msg} ->
        {:error, msg}
    end
  end

  # OPNsense action envelopes: {"result"/"status": "saved"/"deleted"/...}.
  defp action_ok?(%{} = data) do
    token = String.downcase(to_string(data["result"] || data["status"] || ""))
    String.trim(token) in ["saved", "deleted", "enabled", "disabled", "ok", "done"]
  end

  defp action_ok?(_), do: false

  defp upstream_msg(%{"validations" => v}) when v not in [nil, %{}],
    do: "validation error: #{inspect(v)}"

  defp upstream_msg(%{} = data),
    do: to_string(data["result"] || data["status"] || "firewall error")

  defp upstream_msg(_), do: "firewall error"

  # http.relay via the agent (push/relay), else the direct OPNsense API.
  defp relay(inst, method, path, body, opts) do
    case Keyword.get(opts, :relay) do
      fun when is_function(fun, 3) ->
        fun.(method, path, body)

      nil ->
        if Instance.agent_mode?(inst),
          do: relay_via_agent(inst, method, path, body, opts),
          else: relay_via_direct(inst, method, path, body)
    end
  end

  defp relay_via_agent(inst, method, path, body, opts) do
    hub = Keyword.get(opts, :hub, Hub)
    raw = if body, do: Jason.encode!(body), else: ""

    headers =
      %{"Accept" => "application/json"}
      |> then(&if(body, do: Map.put(&1, "Content-Type", "application/json"), else: &1))

    params = %{
      "method" => method,
      "path" => String.trim_leading(path, "/"),
      "headers" => headers,
      "body" => Base.encode64(raw)
    }

    case Hub.send_command_on(hub, inst.id, "http.relay", params, @relay_timeout_ms) do
      {:error, :not_connected} ->
        {:error, "agent not connected"}

      result when is_map(result) ->
        decode_relay(result)

      _ ->
        {:error, "relay failed"}
    end
  end

  defp decode_relay(result) do
    status = to_int(result["status"], 0)

    cond do
      status == 0 -> {:error, to_string(result["output"] || "relay failed")}
      status >= 400 -> {:error, "HTTP #{status}"}
      true -> decode_body(result["body"])
    end
  end

  defp decode_body(b64) do
    with {:ok, raw} <- Base.decode64(to_string(b64 || "")),
         {:ok, json} <- Jason.decode(if(raw == "", do: "{}", else: raw)) do
      {:ok, json}
    else
      _ -> {:error, "invalid JSON response"}
    end
  end

  defp relay_via_direct(inst, method, path, body) do
    with {:ok, client} <- OpnsenseClient.new(inst) do
      case OpnsenseClient.api_json(client, method, path, body) do
        {:ok, data} -> {:ok, data}
        _ -> {:error, "opnsense api error"}
      end
    else
      _ -> {:error, "direct-poll client unavailable"}
    end
  end

  # -- rule normalisation (normalize_rule + _field_text port) ---------------

  @doc false
  def normalize_rule(row) do
    uuid = to_string(row["uuid"] || row["@uuid"] || "")
    legacy = truthy(row["legacy"]) or truthy(row["internal"])
    disabled = truthy(row["disabled"])
    enabled = if Map.has_key?(row, "enabled"), do: truthy(row["enabled"]), else: not disabled

    %{
      uuid: uuid,
      editable: uuid != "" and not legacy,
      enabled: enabled,
      log: truthy(row["log"]),
      action: field_text(row["action"] || row["%action"]),
      direction: field_text(row["direction"] || row["%direction"]),
      protocol: field_text(row["protocol"]),
      interfaces: field_text(row["interface"]),
      source: field_text(row["source_net"] || row["source"]),
      source_port: field_text(row["source_port"]),
      destination: field_text(row["destination_net"] || row["destination"]),
      destination_port: field_text(row["destination_port"]),
      description: field_text(row["description"])
    }
  end

  defp field_text(nil), do: ""
  defp field_text(v) when is_binary(v) or is_number(v) or is_boolean(v), do: to_string(v)

  defp field_text(v) when is_list(v),
    do: v |> Enum.map(&field_text/1) |> Enum.reject(&(&1 == "")) |> Enum.join(", ")

  defp field_text(%{} = v) do
    # A selected option object → its value/label; else the truthy keys.
    selected =
      Enum.find_value(v, fn
        {_k, item} when is_map(item) ->
          if truthy(item["selected"]), do: item["value"] || item["label"]

        _ ->
          nil
      end)

    cond do
      is_binary(v["selected"]) ->
        v["selected"]

      is_binary(v["value"]) ->
        v["value"]

      selected != nil ->
        field_text(selected)

      true ->
        v
        |> Enum.filter(fn {_k, item} -> truthy(item) end)
        |> Enum.map_join(", ", &to_string(elem(&1, 0)))
    end
  end

  defp field_text(v), do: to_string(v)

  defp truthy(v) when is_boolean(v), do: v
  defp truthy(nil), do: false
  defp truthy(v), do: String.downcase(String.trim(to_string(v))) in ~w(1 true yes y on enabled)

  defp to_int(v, default) do
    case Integer.parse(to_string(v || "")) do
      {n, ""} -> n
      _ -> default
    end
  end

  defp audit(opts, inst, action, result, data) do
    sink = Keyword.get(opts, :audit, &Orbit.Audit.write/1)

    sink.(
      action: action,
      result: result,
      user_id: opts[:user_id],
      target_type: "instance",
      target_id: inst.id,
      detail: %{"uuid" => data["uuid"]}
    )
  end
end
