// API client. Session lives in an httpOnly cookie. An optional bearer token
// (scripted access) goes in the Authorization header — never in a URL.
import { local } from "./local";

const BASE = "/api/v1";

let bearer: string | null = local.get("dg_token");

export function setToken(t: string | null) {
  bearer = t;
  if (t) local.set("dg_token", t);
  else local.del("dg_token");
}

/** Called once when any request comes back 401 — the session ended under us
 *  (expiry, sign-out in another tab, a restart that rotated the secret). */
let onUnauthorized: () => void = () => {};
export function whenUnauthorized(f: () => void) { onUnauthorized = f; }

function headers(json = false): HeadersInit {
  const h: Record<string, string> = {};
  if (json) h["Content-Type"] = "application/json";
  if (bearer) h["Authorization"] = "Bearer " + bearer;
  return h;
}

export class ApiError extends Error {
  // no parameter properties: the lib is also run type-stripped under node
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** fetch() rejects with a bare TypeError when nothing answers. Say what that
 *  means, so a toast reads "cannot reach" rather than "Failed to fetch". */
function unreachable(): never {
  throw new ApiError(0, "Cannot reach the Trench daemon — it may be restarting or stopped.");
}

async function handle(r: Response, path: string): Promise<any> {
  if (r.status === 204) return null;
  const text = await r.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!r.ok) {
    if (r.status === 401 && !path.startsWith("/auth/")) onUnauthorized();
    const msg = (data && data.error) || (typeof data === "string" && data) || r.statusText;
    throw new ApiError(r.status, msg);
  }
  return data;
}

function call(method: string, p: string, body?: unknown): Promise<any> {
  const json = body !== undefined || method === "POST" || method === "PUT";
  return fetch(BASE + p, {
    method, credentials: "include", headers: headers(json),
    body: json ? JSON.stringify(body ?? {}) : undefined,
  }).then((r) => handle(r, p), unreachable);
}

export const api = {
  get: (p: string) => call("GET", p),
  post: (p: string, body?: unknown) => call("POST", p, body ?? {}),
  put: (p: string, body?: unknown) => call("PUT", p, body ?? {}),
  del: (p: string, body?: unknown) => call("DELETE", p, body),
  // build a query string, dropping empty values
  qs: (params: Record<string, unknown>) => {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
    }
    const s = u.toString();
    return s ? "?" + s : "";
  },
};
