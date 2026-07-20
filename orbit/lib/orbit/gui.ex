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
  the forwarder, mint a 60s handoff token, opt-in replay the firewall login
  and stash its cookies, and return the handoff URL.
  Callers own scoping + the agent.gui_open audit.
  """
  def open_flow(%Instance{} = inst, path) do
    Orbit.GUI.TunnelManager.ensure(inst.id)
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
  Per-instance GUI origin — a host on the SAME port as the app, handled by
  OrbitWeb.GuiProxy. With a template set (prod: `https://gui-<slug>.<domain>`
  behind TLS termination), {slug}/{id} are substituted. Without one (dev),
  the origin is `http://<slug>.localhost:<port>` — the browser hits orbit,
  which host-matches, gates and reverse-proxies to the firewall over the
  internal forwarder. No proxy sidecar, no per-instance published ports.
  """
  def base_url(%Instance{} = inst) do
    case Application.get_env(:orbit, :gui_base_template, "") do
      "" ->
        port = Application.get_env(:orbit, :gui_dev_port, 8000)
        "http://#{inst.slug}.localhost:#{port}"

      template ->
        template
        |> String.replace("{slug}", to_string(inst.slug))
        |> String.replace("{id}", to_string(inst.id))
    end
  end

  @doc """
  The URL the browser opens for the GUI: the handoff — `/__orbit/auth?t=`.

  Same shape in dev and prod, because the same code answers it: the request
  lands on orbit's own port, `OrbitWeb.GuiProxy` host-matches the origin,
  exchanges the token for the `orbit_gui` cookie and gates every asset from
  there. Only the host differs (`<slug>.localhost:<port>` vs the configured
  `gui-<slug>.<domain>`).
  """
  def handoff_url(inst, token, path) do
    base = base_url(inst)
    url = "#{base}/__orbit/auth?t=#{token}"
    nxt = safe_next(path)
    if nxt == "/", do: url, else: url <> "&next=" <> URI.encode(nxt, &URI.char_unreserved?/1)
  end
end
