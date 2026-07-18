defmodule OrbitWeb.SecurityLive do
  @moduledoc """
  Self-service 2FA management (SecurityPage.tsx port) — any authenticated user
  manages their OWN authenticator + passkeys. Shows TOTP status and the passkey
  list; adds a passkey via the WebAuthn ceremony (the `Passkey` JS hook drives
  `navigator.credentials.create`, the challenge lives only in this LiveView's
  process state between the two events) and removes one, never the account's
  last remaining second factor.

  Passkey login (assertion) is a separate slice; here TOTP is read-only status
  (re-enrollment stays an admin 2FA-reset, mirroring the python page).
  """

  use OrbitWeb, :live_view

  require Logger

  alias Orbit.Accounts
  alias Orbit.Audit
  alias Orbit.Auth.Webauthn

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket |> assign(error: nil, wa_challenge: nil) |> load()}
  end

  defp load(socket) do
    methods = Accounts.mfa_methods(socket.assigns.current_user)
    assign(socket, totp_enabled: methods.totp_enabled, passkeys: methods.passkeys)
  end

  # Step 1 of add: mint options + stash the challenge, reply to the JS hook.
  @impl true
  def handle_event("passkey_register_begin", _params, socket) do
    user = socket.assigns.current_user

    {options, challenge} =
      Webauthn.registration_options(user.id, user.username, socket.assigns.passkeys)

    {:reply, %{options: options}, assign(socket, wa_challenge: challenge, error: nil)}
  end

  # Step 2: verify the attestation against the stashed challenge, persist, audit.
  def handle_event("passkey_register_finish", _p, %{assigns: %{wa_challenge: nil}} = socket) do
    {:noreply, assign(socket, error: "Passkey registration expired — try again.")}
  end

  def handle_event("passkey_register_finish", %{"credential" => credential} = params, socket) do
    challenge = socket.assigns.wa_challenge
    socket = assign(socket, wa_challenge: nil)
    user = socket.assigns.current_user

    with {:ok, verified} <- Webauthn.verify_registration(credential, challenge),
         {:ok, cred} <- Accounts.add_credential(user, verified, params["name"]) do
      audit(socket, "auth.mfa_passkey_add", "ok", to_string(cred.id))
      {:noreply, socket |> assign(error: nil) |> load()}
    else
      {:error, %Ecto.Changeset{}} ->
        {:noreply, assign(socket, error: "That passkey is already registered.")}

      {:error, reason} ->
        Logger.info("webauthn.register_failed user_id=#{user.id} reason=#{inspect(reason)}")
        {:noreply, assign(socket, error: "Passkey registration failed.")}
    end
  end

  # Browser-side ceremony failure (user dismissed the prompt, no authenticator…).
  def handle_event("passkey_error", %{"message" => message}, socket) do
    {:noreply, assign(socket, wa_challenge: nil, error: to_string(message))}
  end

  def handle_event("remove_passkey", %{"id" => id}, socket) do
    user = socket.assigns.current_user

    case Accounts.delete_credential(user, to_int(id)) do
      {:ok, cred} ->
        audit(socket, "auth.mfa_passkey_remove", "ok", to_string(cred.id))
        {:noreply, socket |> assign(error: nil) |> load()}

      {:error, :last_factor} ->
        {:noreply, assign(socket, error: "You can't remove your only second factor.")}

      {:error, :not_found} ->
        {:noreply, assign(socket, error: "Passkey not found.")}
    end
  end

  # source_ip is the documented LiveView audit seam (get_connect_info is only
  # readable in mount/3, and track_access already records the operator IP per
  # request) — left nil here, matching settings_live/instance_detail_live.
  defp audit(socket, action, result, target_id) do
    Audit.write(
      action: action,
      result: result,
      user_id: socket.assigns.current_user.id,
      target_type: "user",
      target_id: target_id
    )
  end

  defp to_int(v) when is_integer(v), do: v

  defp to_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> -1
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:security} current_user={@current_user} />

      <section class="mx-auto max-w-2xl p-6">
        <h1 class="text-lg font-medium text-base-content">Security</h1>
        <p class="mt-1 text-sm text-base-content/70">
          Two-factor authentication is mandatory. Manage your authenticator and passkeys here.
        </p>

        <div
          :if={@error}
          class="mt-4 rounded-lg border border-error/40 bg-error/10 px-3 py-2 text-sm text-error"
        >
          {@error}
        </div>

        <div class="mt-5 rounded-xl border border-base-300 bg-base-200/60 p-5">
          <h3 class="text-sm font-semibold text-base-content">Authenticator app (TOTP)</h3>
          <p class="mt-1 text-sm text-base-content/70">
            {if @totp_enabled,
              do: "Enabled. To re-enroll, ask an admin to reset your 2FA.",
              else: "Not enabled — you signed in with a passkey."}
          </p>
        </div>

        <div class="mt-5 rounded-xl border border-base-300 bg-base-200/60 p-5">
          <h3 class="text-sm font-semibold text-base-content">Passkeys</h3>

          <div class="mt-3 flex items-center gap-2">
            <input
              id="passkey-name"
              type="text"
              placeholder="Passkey name (optional)"
              maxlength="128"
              class="w-56 rounded-lg border border-base-content/20 bg-base-300 px-3 py-1.5 text-sm text-base-content focus:border-primary focus:outline-none"
            />
            <button
              id="passkey-add"
              type="button"
              phx-hook="Passkey"
              class="inline-flex items-center gap-1 rounded-lg bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary disabled:opacity-50"
            >
              Add passkey
            </button>
          </div>

          <table class="mt-4 w-full text-sm">
            <tbody>
              <tr :if={@passkeys == []}>
                <td class="py-2 text-xs text-base-content/60">No passkeys registered.</td>
              </tr>
              <tr :for={p <- @passkeys} class="border-t border-base-300">
                <td class="py-2 text-base-content">{p.name || "Passkey ##{p.id}"}</td>
                <td class="py-2 text-xs text-base-content/70">{used_text(p)}</td>
                <td class="py-2 text-right">
                  <button
                    type="button"
                    phx-click="remove_passkey"
                    phx-value-id={p.id}
                    class="rounded px-2 py-1 text-xs text-error hover:bg-base-300"
                  >
                    Remove
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  defp used_text(%{last_used_at: nil}), do: "never used"

  defp used_text(%{last_used_at: at}),
    do: "last used " <> Calendar.strftime(at, "%Y-%m-%d %H:%M UTC")
end
