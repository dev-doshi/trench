// Global reactive store + live WebSocket manager. No Pinia — Vue reactivity
// covers a single-store app and keeps the dependency surface at zero.
//
// WS protocol (server: trench/api/server.py `websocket`):
//   {type:"hello", data:{stats, series, recent}}   on connect
//   {type:"query", data:QueryEvent}                per resolved query
//   {type:"stats", data:Stats, series?, dropped?}  periodic snapshot; `dropped`
//                                                  counts events this connection
//                                                  missed by falling behind
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
  dropped: 0,                     // events the server skipped: this tab fell behind
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
let retry: ReturnType<typeof setTimeout> | null = null;

function pushLive(ev: QueryEvent) {
  s.liveTotal++;
  if (s.paused) return;
  s.live.unshift(ev);
  if (s.live.length > liveCap) s.live.length = liveCap;
}

function connect() {
  retry = null;
  if (stopped) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const sock = new WebSocket(`${proto}://${location.host}/api/v1/ws`);
  ws = sock;
  s.conn = "connecting";
  // Every handler checks it still belongs to the current socket. A socket
  // closed by stopWs() reports its close later, asynchronously — after a
  // startWs() that followed (log out, log in) has already opened the next one
  // — and used to schedule a reconnect of its own: two sockets, every event
  // shown twice, and one more per repeat.
  sock.onopen = () => {
    if (ws !== sock) return;
    backoff = 500; s.conn = "live";
  };
  sock.onmessage = (m) => {
    if (ws !== sock) return;
    let frame: any;
    try { frame = JSON.parse(m.data); } catch { return; }
    if (frame.type === "hello") {
      s.stats = frame.data.stats;
      s.series = frame.data.series || [];
      s.live = (frame.data.recent || []).slice(0, liveCap);
      s.dropped = 0;
    } else if (frame.type === "query") {
      pushLive(frame.data);
    } else if (frame.type === "stats") {
      s.stats = frame.data;
      if (frame.series) s.series = frame.series;
      // events the server skipped because this tab fell behind, per connection
      if (typeof frame.dropped === "number") s.dropped = frame.dropped;
    }
  };
  sock.onclose = () => {
    if (stopped || ws !== sock) return;
    s.conn = "reconnecting";
    // jittered, so every console open on a restarted server does not
    // reconnect in the same instant
    retry = setTimeout(connect, backoff * (0.75 + Math.random() * 0.5));
    backoff = Math.min(backoff * 1.7, 8000);
  };
  sock.onerror = () => sock.close();
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
  startWs() {
    stopped = false;
    if (retry === null && (!ws || ws.readyState > 1)) connect();
  },
  stopWs() {
    stopped = true;
    if (retry !== null) { clearTimeout(retry); retry = null; }
    ws?.close(); ws = null; s.conn = "offline";
  },
};

applyPrefs();
