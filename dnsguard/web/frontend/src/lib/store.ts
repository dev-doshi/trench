// Global reactive store + live WebSocket manager. No Pinia — Vue reactivity
// covers a single-store app and keeps the dependency surface at zero.
//
// WS protocol (server: dnsguard/api/server.py `websocket`):
//   {type:"hello", data:{stats, series, recent}}   on connect
//   {type:"query", data:QueryEvent}                per resolved query
//   {type:"stats", data:Stats, series?}            periodic snapshot
import { reactive, readonly } from "vue";

export interface QueryEvent {
  ts: number; client: string; domain: string; type: string;
  action: string; rcode: string; upstream: string; elapsed_us: number; reason: string;
}

export interface Stats {
  uptime: number; total: number; blocked: number; cached: number; forwarded: number;
  failed: number; block_pct: number; avg_latency_ms: number;
  latency_p50_ms: number; latency_p95_ms: number; latency_p99_ms: number;
  by_qtype: [string, number][]; by_rcode: [string, number][];
  top_queries: [string, number][]; top_blocked: [string, number][];
  top_clients: [string, number][]; top_upstreams: [string, number][];
  dga_flagged: number; top_dga: [string, number][];
  tunnel_flagged: number; top_tunnel: [string, number][];
  enabled: boolean; blocklist_size: number; cache_size: number;
  cache_stats?: Record<string, number>; version: string;
}

export type SeriesPoint = {
  t: number; total: number; blocked: number; cached: number;
  forwarded: number; failed: number; latency_ms: number;
};

export interface Toast { id: number; title: string; detail?: string; err?: boolean; }

let liveCap = Number(localStorage.getItem("dg_livecap")) || 600;

const s = reactive({
  user: null as { name: string; role: string } | null,
  conn: "connecting" as "live" | "reconnecting" | "connecting" | "offline",
  stats: null as Stats | null,
  series: [] as SeriesPoint[],
  live: [] as QueryEvent[],       // newest first, capped at liveCap
  liveTotal: 0,                   // events observed since load (even when paused)
  paused: false,
  toasts: [] as Toast[],
  // global entity inspector (ui/Inspector.vue): open from anywhere via
  // store.inspect("domain"|"client", value)
  inspecting: null as { kind: "domain" | "client"; value: string } | null,
  prefs: {
    density: (localStorage.getItem("dg_density") || "comfortable") as "comfortable" | "compact",
    colorblind: localStorage.getItem("dg_cb") === "1",
    expert: localStorage.getItem("dg_expert") === "1",
    motion: (localStorage.getItem("dg_motion") || "auto") as "auto" | "off",
    hour12: localStorage.getItem("dg_hour12") === "1",
    livecap: liveCap,
    pagesize: Number(localStorage.getItem("dg_pagesize")) || 100,
  },
});

let toastId = 0;
function toast(title: string, detail?: string, err = false) {
  const id = ++toastId;
  s.toasts.push({ id, title, detail, err });
  setTimeout(() => {
    const i = s.toasts.findIndex((t) => t.id === id);
    if (i >= 0) s.toasts.splice(i, 1);
  }, 4200);
}

function applyPrefs() {
  const el = document.documentElement;
  el.dataset.density = s.prefs.density;
  el.dataset.cb = s.prefs.colorblind ? "on" : "off";
  el.dataset.motion = s.prefs.motion;
  liveCap = s.prefs.livecap;
  localStorage.setItem("dg_density", s.prefs.density);
  localStorage.setItem("dg_cb", s.prefs.colorblind ? "1" : "0");
  localStorage.setItem("dg_expert", s.prefs.expert ? "1" : "0");
  localStorage.setItem("dg_motion", s.prefs.motion);
  localStorage.setItem("dg_hour12", s.prefs.hour12 ? "1" : "0");
  localStorage.setItem("dg_livecap", String(s.prefs.livecap));
  localStorage.setItem("dg_pagesize", String(s.prefs.pagesize));
}

// ---- WebSocket manager (auto-reconnect with backoff) ----
let ws: WebSocket | null = null;
let backoff = 500;
let stopped = false;

function pushLive(ev: QueryEvent) {
  s.liveTotal++;
  if (s.paused) return;
  s.live.unshift(ev);
  if (s.live.length > liveCap) s.live.length = liveCap;
}

function connect() {
  if (stopped) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/api/v1/ws`);
  s.conn = "connecting";
  ws.onopen = () => { backoff = 500; s.conn = "live"; };
  ws.onmessage = (m) => {
    let frame: any;
    try { frame = JSON.parse(m.data); } catch { return; }
    if (frame.type === "hello") {
      s.stats = frame.data.stats;
      s.series = frame.data.series || [];
      s.live = (frame.data.recent || []).slice(0, liveCap);
    } else if (frame.type === "query") {
      pushLive(frame.data);
    } else if (frame.type === "stats") {
      s.stats = frame.data;
      if (frame.series) s.series = frame.series;
    }
  };
  ws.onclose = () => {
    if (stopped) return;
    s.conn = "reconnecting";
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 1.7, 8000);
  };
  ws.onerror = () => ws?.close();
}

export const store = {
  state: readonly(s) as unknown as typeof s,
  toast,
  setUser: (u: typeof s.user) => { s.user = u; },
  togglePause: () => { s.paused = !s.paused; },
  inspect: (kind: "domain" | "client", value: string) => { s.inspecting = { kind, value }; },
  closeInspector: () => { s.inspecting = null; },
  clearLive: () => { s.live = []; },
  setPref<K extends keyof typeof s.prefs>(k: K, v: (typeof s.prefs)[K]) {
    s.prefs[k] = v; applyPrefs();
  },
  startWs() { stopped = false; if (!ws || ws.readyState > 1) connect(); },
  stopWs() { stopped = true; ws?.close(); ws = null; s.conn = "offline"; },
};

applyPrefs();
