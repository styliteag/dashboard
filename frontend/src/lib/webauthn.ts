/**
 * Passkey (WebAuthn) helpers. Each pairs a server "options" call with the
 * browser ceremony and the matching "verify" call. The login variants return the
 * authenticated User (the session is minted server-side); the manage variants run
 * while already signed in.
 */
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { api } from "./api";
import type { User } from "./use-auth";

type RegOptions = Parameters<typeof startRegistration>[0]["optionsJSON"];
type AuthOptions = Parameters<typeof startAuthentication>[0]["optionsJSON"];

export interface Passkey {
  id: number;
  name: string | null;
  created_at: string;
  last_used_at: string | null;
}

/** Enroll a passkey during the forced-2FA login step; mints the session. */
export async function passkeyEnroll(name?: string): Promise<User> {
  const optionsJSON = await api.post<RegOptions>("/api/auth/mfa/webauthn/register/options");
  const credential = await startRegistration({ optionsJSON });
  return api.post<User>("/api/auth/mfa/webauthn/register/verify", { credential, name });
}

/** Log in with an existing passkey (login step 2); mints the session. */
export async function passkeyAuthenticate(): Promise<User> {
  const optionsJSON = await api.post<AuthOptions>("/api/auth/mfa/webauthn/auth/options");
  const credential = await startAuthentication({ optionsJSON });
  return api.post<User>("/api/auth/mfa/webauthn/auth/verify", { credential });
}

/** Add a passkey to the signed-in account. */
export async function passkeyAdd(name?: string): Promise<Passkey> {
  const optionsJSON = await api.post<RegOptions>("/api/auth/mfa/webauthn/manage/options");
  const credential = await startRegistration({ optionsJSON });
  return api.post<Passkey>("/api/auth/mfa/webauthn/manage/verify", { credential, name });
}
