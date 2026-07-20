defmodule Orbit.GUI.Caddy do
  @moduledoc """
  Build the GUI-proxy Caddyfile from the DB and hot-load it via Caddy's
  admin API — port of gui_caddy.py. The public host is a per-instance slug
  (gui-<slug>.<domain>), so the host→port binding lives in the DB; on every
  instance create/slug-change/delete (and at boot) the file is rebuilt and
  POSTed to Caddy's /load (no restart). The forwarder port is a stable
  14400 + id (never reused across instances → a per-origin cookie can't
  leak across firewalls), and the instance id is baked into each vhost's
  forward_auth ?instance=<id> so authcheck needs no host parsing.

  build_caddyfile/1 is pure (unit-tested); reconcile/0 is best-effort — a
  push failure logs and returns false, never raises (a transient Caddy
  outage must not break instance CRUD; the next change re-pushes).
  """

  require Logger

  @forwarder_base 14_400

  def forwarder_base, do: @forwarder_base
  def port_for(instance_id), do: @forwarder_base + instance_id

  @global """
  # GENERATED — pushed by orbit via Caddy's admin API (Orbit.GUI.Caddy).
  {
  \tadmin 0.0.0.0:2019
  \tauto_https off
  }

  (gui_vhost) {
  \t@orbit path /__orbit/*
  \thandle @orbit {
  \t\trewrite * /api/gui/handoff?{query}
  \t\treverse_proxy {$ORBIT_GUI_APP:app:80}
  \t}
  \thandle {
  \t\tforward_auth {$ORBIT_GUI_APP:app:80} {
  \t\t\turi /api/gui/authcheck?instance={args[1]}
  \t\t}
  \t\treverse_proxy {$ORBIT_GUI_FWD_HOST:app}:{args[0]} {
  \t\t\ttransport http {
  \t\t\t\ttls
  \t\t\t\ttls_insecure_skip_verify
  \t\t\t}
  \t\t}
  \t}
  }
  """

  @doc "Render the Caddyfile for {slug, id} pairs (empty = bootstrap)."
  def build_caddyfile(instances) do
    body =
      Enum.map_join(instances, "", fn {slug, id} ->
        "\t@gui-#{slug} host gui-#{slug}.{$ORBIT_GUI_DOMAIN}\n" <>
          "\thandle @gui-#{slug} {\n" <>
          "\t\timport gui_vhost #{port_for(id)} #{id}\n" <>
          "\t}\n"
      end)

    @global <> "\nhttp://*.{$ORBIT_GUI_DOMAIN} {\n" <> body <> "}\n"
  end

  def bootstrap_caddyfile, do: build_caddyfile([])

  @doc "Rebuild from live instances + hot-load. No-op/false when off or unset."
  def reconcile(opts \\ []) do
    if enabled?() do
      url = Application.get_env(:orbit, :gui_caddy_admin_url, "")
      config = build_caddyfile(live_instances())
      push(url, config, opts)
    else
      false
    end
  end

  @doc """
  Reconcile off the caller's process — the instance-CRUD path.

  The moduledoc has claimed a rebuild "on every instance create/slug-change/
  delete (and at boot)" since this module was written, but the only caller was
  the open-a-GUI-session flow. A renamed slug therefore kept serving the OLD
  vhost, and a deleted instance kept a live one, until somebody happened to
  open a GUI session for ANY box. Now the claim is true.

  Fire-and-forget by design: the push is an HTTP call to a sidecar that may be
  down or slow, and creating a firewall must not wait on it (the moduledoc's
  own rule — a transient Caddy outage must not break instance CRUD). The gate
  is checked before spawning so a disabled proxy costs nothing at all.
  """
  def reconcile_async do
    if enabled?() do
      Task.start(fn -> reconcile() end)
    end

    :ok
  end

  defp enabled? do
    Application.get_env(:orbit, :gui_proxy_enabled, false) and
      Application.get_env(:orbit, :gui_caddy_admin_url, "") != ""
  end

  defp push(url, config, opts) do
    base = [
      url: url,
      body: config,
      headers: [{"content-type", "text/caddyfile"}],
      receive_timeout: 10_000,
      retry: false
    ]

    req_opts =
      case Keyword.get(opts, :req_plug, Application.get_env(:orbit, :caddy_req_plug)) do
        nil -> base
        plug -> Keyword.put(base, :plug, plug)
      end

    case Req.post(req_opts) do
      {:ok, %{status: status}} when status < 400 ->
        Logger.info(
          "gui_caddy.pushed vhosts=#{config |> String.split("@gui-") |> length() |> Kernel.-(1)}"
        )

        true

      {:ok, %{status: status}} ->
        Logger.warning("gui_caddy.push_failed status=#{status} url=#{url}")
        false

      {:error, error} ->
        Logger.warning("gui_caddy.push_failed error=#{Exception.message(error)} url=#{url}")
        false
    end
  end

  defp live_instances do
    import Ecto.Query

    Orbit.Repo.all(
      from(i in Orbit.Instances.Instance,
        where: is_nil(i.deleted_at),
        order_by: i.id,
        select: {i.slug, i.id}
      )
    )
  rescue
    _ -> []
  end
end
