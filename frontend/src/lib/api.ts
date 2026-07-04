/**
 * Thin fetch wrapper used by every component. Cookies (session) are sent
 * with every request; non-2xx responses raise ApiError so React Query
 * routes them through onError consistently.
 */

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** The server's error message when `e` is an ApiError, else the fallback. */
export function apiErrorText(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

/** FastAPI `detail` → readable text. Validation errors arrive as an array of
 *  {loc, msg, type} objects — `String()` on those renders "[object Object]". */
function detailText(detail: unknown): string {
  if (Array.isArray(detail)) {
    return detail
      .map((d) =>
        d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : String(d),
      )
      .join("; ");
  }
  return String(detail);
}

export const unauthorizedEvent = "dash:unauthorized";

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

let authToken = localStorage.getItem("dash_session_token");

export function setAuthToken(token: string | null) {
  authToken = token;
  if (token) localStorage.setItem("dash_session_token", token);
  else localStorage.removeItem("dash_session_token");
}

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: "include",
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
  };
  if (body !== undefined) init.body = JSON.stringify(body);

  const res = await fetch(path, init);

  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
  }

  if (!res.ok) {
    if (res.status === 401) {
      setAuthToken(null);
      window.dispatchEvent(new Event(unauthorizedEvent));
    }

    const detail =
      (parsed && typeof parsed === "object" && "detail" in parsed
        ? detailText((parsed as { detail: unknown }).detail)
        : null) ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, detail, parsed);
  }

  return parsed as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  del: <T = void>(path: string) => request<T>("DELETE", path),
};
