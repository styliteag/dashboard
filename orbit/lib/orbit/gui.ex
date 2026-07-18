defmodule Orbit.GUI do
  @moduledoc """
  GUI-proxy facade (§18) — the open-flow logic behind the controller, kept
  here so it is unit-testable without HTTP. Ports the pure parts of
  routes/gui.py: the open-redirect-safe next clamp and the per-instance
  origin URL.
  """

  require Logger

  alias Orbit.GUI.Auth
  alias Orbit.Instances.Instance

  @doc """
  Whether the GUI proxy can be opened for this instance right now: enabled
  globally, the device has a web UI, and its agent is connected. Returns
  `:ok` or `{:error, reason}` (parity with the controller's guard ladder).
  """
  def openable(%Instance{} = inst) do
    cond do
      not Application.get_env(:orbit, :gui_proxy_enabled, false) -> {:error, :disabled}
      inst.device_type in ["linux"] -> {:error, :no_webif}
      Orbit.Hub.get(inst.id) == nil -> {:error, :not_connected}
      true -> :ok
    end
  end

  @doc """
  The open flow shared by the controller and the LiveView button: ensure
  the forwarder + Caddy vhost, mint a 60s handoff token, opt-in replay the
  firewall login and stash its cookies, and return the handoff URL.
  Callers own scoping + the agent.gui_open audit.
  """
  def open_flow(%Instance{} = inst, path) do
    Orbit.GUI.TunnelManager.ensure(inst.id)
    Orbit.GUI.Caddy.reconcile()
    token = Auth.sign(inst.id, 60)
    maybe_stash_login(inst, token)
    handoff_url(inst, token, path)
  end

  defp maybe_stash_login(%Instance{gui_login_enabled: true, id: id}, token) do
    case Orbit.Hub.send_command(id, "gui.login", %{}, 20_000) do
      %{"success" => true, "cookies" => cookies} when is_list(cookies) ->
        pairs = for c <- cookies, is_map(c), do: {c["name"], c["value"]}
        Orbit.GUI.SessionStash.put(token, pairs, 60)

      other ->
        Logger.warning(
          "agent.gui_login_failed instance=#{id} output=#{inspect(is_map(other) && other["output"])}"
        )
    end
  end

  defp maybe_stash_login(_inst, _token), do: :ok

  @doc """
  Clamp a handoff deep-link to a same-origin absolute path (open-redirect
  defense): only "/..." passes; absolute URLs, protocol-relative "//host"
  and backslash variants (browsers normalize to "//") all collapse to "/".
  """
  def safe_next(path)
      when is_binary(path) do
    if String.starts_with?(path, "/") and not String.starts_with?(path, "//") and
         not String.contains?(path, "\\") do
      path
    else
      "/"
    end
  end

  def safe_next(_), do: "/"

  @doc """
  Per-instance GUI origin. With a template set (prod: gui-<slug>.<domain>
  behind the front reverse proxy), {slug}/{id} are substituted. Without one
  the dev port convention https://localhost:900{id} is used — that origin
  must be fronted by a reverse proxy (nginx/Caddy) that rewrites /__orbit/*
  to the handoff, gates on the orbit_gui cookie via /api/gui/authcheck and
  proxies the rest to this instance's forwarder port (14400 + id).
  """
  def base_url(%Instance{} = inst) do
    case Application.get_env(:orbit, :gui_base_template, "") do
      "" ->
        "https://localhost:#{9000 + inst.id}"

      template ->
        template
        |> String.replace("{slug}", to_string(inst.slug))
        |> String.replace("{id}", to_string(inst.id))
    end
  end

  @doc "Build the handoff URL for a minted token + optional deep-link path."
  def handoff_url(inst, token, path) do
    url = "#{base_url(inst)}/__orbit/auth?t=#{token}"
    nxt = safe_next(path)
    if nxt == "/", do: url, else: url <> "&next=" <> URI.encode(nxt, &URI.char_unreserved?/1)
  end
end
