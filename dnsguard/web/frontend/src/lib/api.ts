// API client. Session lives in an httpOnly cookie. An optional bearer token
// (scripted access) goes in the Authorization header — never in a URL.
const BASE = "/api/v1";

let bearer: string | null = localStorage.getItem("dg_token");

export function setToken(t: string | null) {
  bearer = t;
  if (t) localStorage.setItem("dg_token", t);
  else localStorage.removeItem("dg_token");
}

function headers(json = false): HeadersInit {
  const h: Record<string, string> = {};
  if (json) h["Content-Type"] = "application/json";
  if (bearer) h["Authorization"] = "Bearer " + bearer;
  return h;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function handle(r: Response): Promise<any> {
  if (r.status === 204) return null;
  const text = await r.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!r.ok) {
    const msg = (data && data.error) || (typeof data === "string" && data) || r.statusText;
    throw new ApiError(r.status, msg);
  }
  return data;
}

export const api = {
  get: (p: string) =>
    fetch(BASE + p, { credentials: "include", headers: headers() }).then(handle),
  post: (p: string, body?: unknown) =>
    fetch(BASE + p, { method: "POST", credentials: "include", headers: headers(true), body: JSON.stringify(body ?? {}) }).then(handle),
  put: (p: string, body?: unknown) =>
    fetch(BASE + p, { method: "PUT", credentials: "include", headers: headers(true), body: JSON.stringify(body ?? {}) }).then(handle),
  del: (p: string) =>
    fetch(BASE + p, { method: "DELETE", credentials: "include", headers: headers() }).then(handle),
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
