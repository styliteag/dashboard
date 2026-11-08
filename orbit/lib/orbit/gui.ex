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
      # Linux-line nodes: proxmox/truenas do have web UIs, but the agent's
      # gui.login session-minting only exists on the firewall platforms.
      Orbit.Agent.Package.linux_line?(inst.device_type) -> {:error, :no_webif}
      Orbit.Hub.get(inst.id) == nil -> {:error, :not_connected}
      true -> :ok
    end
  end

  @doc """
  The open flow shared by the controller and the LiveView button: ensure
  the forwarder, mint a 60s handoff token bound to `user`, opt-in replay the firewall login
  and stash its cookies, and return the handoff URL.
  Callers own scoping + the agent.gui_open audit.
  """
  def open_flow(%Instance{} = inst, path, user) do
    Orbit.GUI.TunnelManager.ensure(inst.id)
    token = Auth.sign_bound(inst.id, user.id, pv(user), 60)
    maybe_stash_login(inst, token)
    handoff_url(inst, token, path)
  end

  defp maybe_stash_login(%Instance{gui_login_enabled: true, id: id}, token) do
    case Orbit.Hub.send_command(id, "gui.login", %{}, 20_000) do
      %{"success" => true, "cookies" => cookies} when is_list(cookies) ->
        pairs =
          for c <- cookies,
              is_map(c),
              pair = {c["name"], c["value"]},
              safe_cookie?(pair),
              do: pair

        Orbit.GUI.SessionStash.put(token, pairs, 60)

      other ->
        Logger.warning(
          "agent.gui_login_failed instance=#{id} output=#{inspect(is_map(other) && other["output"])}"
        )
    end
  end

  defp maybe_stash_login(_inst, _token), do: :ok

  @doc """
  An agent-reported firewall cookie `{name, value}` that may be replayed as
  a Set-Cookie: RFC 6265 token name, value without separators, whitespace
  or control characters (no attribute or header injection).
  """
  def safe_cookie?({name, value}) when is_binary(name) and is_binary(value) do
    Regex.match?(~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\z/, name) and
      Regex.match?(~r/\A[^;,\s\x00-\x1f\x7f"\\]{0,4096}\z/, value)
  end

  def safe_cookie?(_), do: false

  # Lifetime of the `orbit_gui` cookie. Short-ish on purpose: the binding
  # below catches password changes, disabling and scope changes, but not a
  # plain dashboard logout (the session registry is bookkeeping only).
  @cookie_ttl 2 * 3600

  @doc "A fresh `orbit_gui` cookie value for `instance_id`, bound to `user`."
  def cookie_token(instance_id, user),
    do: Auth.sign_bound(instance_id, user.id, pv(user), @cookie_ttl)

  @doc """
  True when `token` is a bound GUI token for `instance_id` whose user still
  exists, is enabled, has the same password_version, and can still see the
  instance (Scope). Checked on the handoff and on every proxied request.
  """
  def authorized?(token, instance_id) do
    with {:ok, %{instance_id: ^instance_id, user_id: uid, password_version: v}} <-
           Auth.verify_bound(token),
         %Orbit.Accounts.User{disabled: disabled} = user when disabled != true <-
           Orbit.Accounts.get_user(uid),
         true <- pv(user) == v,
         %Instance{} <- Orbit.Auth.Scope.get_instance(instance_id, user) do
      true
    else
      _ -> false
    end
  end

  @doc "The user a bound token was minted for (handoff → cookie)."
  def token_user(token) do
    case Auth.verify_bound(token) do
      {:ok, %{user_id: uid}} -> Orbit.Accounts.get_user(uid)
      :error -> nil
    end
  end

  defp pv(user), do: user.password_version || 0

  @doc """
  Clamp a handoff deep-link to a same-origin absolute path (open-redirect
  defense): only "/..." passes; absolute URLs, protocol-relative "//host"
  and backslash variants (browsers normalize to "//") all collapse to "/".
  """
  def safe_next(path)
      when is_binary(path) do
    # Control characters (incl. TAB/CR/LF, which browsers strip, turning
    # "/\t/host" into "//host") and backslashes anywhere, plus encoded
    # CR/LF, never pass.
    if String.starts_with?(path, "/") and not String.starts_with?(path, "//") and
         not String.contains?(path, "\\") and not String.match?(path, ~r/[\x00-\x1f\x7f]/) and
         not String.match?(path, ~r/%0[0-9a-f]|%1[0-9a-f]|%7f/i) do
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
