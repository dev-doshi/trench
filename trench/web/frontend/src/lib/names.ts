// Device names for client addresses, shared by every view.
//
// Server: GET /clients/names → {names: {ip: {name, source, fqdn}}, lookup}.
// `source` is "manual" (set by the operator), "dhcp" (Trench's own leases) or
// "network" (a reverse lookup to the router). A network name is whatever the
// device told the router, so views show the address beside it and say where
// the name came from rather than presenting it as fact.
import { reactive } from "vue";
import { api } from "./api";

export type NameSource = "manual" | "dhcp" | "network";
export interface DeviceName { name: string; source: NameSource; fqdn: string; }

const REFRESH_MS = 3 * 60_000;

const state = reactive({
  byIp: {} as Record<string, DeviceName>,
  lookup: { enabled: false, via: "" },
  loaded: false,
});

let timer: number | undefined;
let inflight: Promise<void> | null = null;

/** Normalise the way the server keys addresses (lower-case IPv6). */
const key = (ip: string) => (ip || "").trim().toLowerCase();

export function refreshNames(): Promise<void> {
  if (inflight) return inflight;
  inflight = api.get("/clients/names").then((d: any) => {
    const out: Record<string, DeviceName> = {};
    for (const [ip, v] of Object.entries<any>(d?.names || {})) {
      if (v && typeof v.name === "string" && v.name) {
        out[key(ip)] = { name: v.name, source: v.source, fqdn: v.fqdn || "" };
      }
    }
    state.byIp = out;
    state.lookup = d?.lookup || { enabled: false, via: "" };
    state.loaded = true;
  }).catch(() => {}).finally(() => { inflight = null; });
  return inflight;
}

/** Start loading names (once per page), and keep them fresh while it is open. */
export function useNames() {
  if (timer === undefined) {
    refreshNames();
    timer = window.setInterval(refreshNames, REFRESH_MS);
  }
  return state;
}

export function nameOf(ip: string): string {
  return state.byIp[key(ip)]?.name || "";
}

export function entryOf(ip: string): DeviceName | undefined {
  return state.byIp[key(ip)];
}

export const SOURCE_TEXT: Record<NameSource, string> = {
  manual: "named by you",
  dhcp: "from Trench's DHCP lease",
  network: "reported by the router (the device's own name)",
};

/** Hover text: the address, where the name came from, and the full name. */
export function nameTitle(ip: string): string {
  const e = entryOf(ip);
  if (!e) return ip;
  const full = e.fqdn && e.fqdn !== e.name ? ` · ${e.fqdn}` : "";
  return `${ip} — ${e.name}, ${SOURCE_TEXT[e.source] || e.source}${full}`;
}

/** "name (ip)" for places that can only hold one string, such as a chart label. */
export function label(ip: string): string {
  const n = nameOf(ip);
  return n ? `${n} (${ip})` : ip;
}
