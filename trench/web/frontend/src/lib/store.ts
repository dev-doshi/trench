// Global reactive store + live WebSocket manager. No Pinia — Vue reactivity
// covers a single-store app and keeps the dependency surface at zero.
//
// WS protocol (server: trench/api/server.py `websocket`):
//   {type:"hello", data:{stats, series, recent}}   on connect
//   {type:"query", data:QueryEvent}                per resolved query
//   {type:"stats", data:Stats, series?, dropped}   periodic snapshot; dropped counts
//                                                  events shed for this socket
import { reactive, readonly } from "vue";
import { local } from "./local";

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

/** How many live events the browser keeps. Enough for the tape and the
 *  inspector's "held here" slice without growing without bound over a long day. */
const LIVE_CAP = 600;

const s = reactive({
  user: null as { name: string; role: string } | null,
  conn: "connecting" as "live" | "reconnecting" | "connecting" | "offline",
  stats: null as Stats | null,
  series: [] as SeriesPoint[],
  live: [] as QueryEvent[],       // newest first, capped at LIVE_CAP
  liveTotal: 0,                   // events observed since load (even when paused)
  /** events the server shed for this tab because it could not keep up — the
   *  tape is a sample, not a record, once this is non-zero */
  dropped: 0,
  paused: false,
  toasts: [] as Toast[],
  // global entity inspector (ui/Inspector.vue): open from anywhere via
  // store.inspect("domain"|"client", value)
  inspecting: null as { kind: "domain" | "client"; value: string } | null,
});

let toastId = 0;
function dismissToast(id: number) {
  const i = s.toasts.findIndex((t) => t.id === id);
  if (i >= 0) s.toasts.splice(i, 1);
}
/** An error stays up twice as long: it is the one toast that has to be read. */
function toast(title: string, detail?: string, err = false) {
  const id = ++toastId;
  s.toasts.push({ id, title, detail, err });
  if (s.toasts.length > 4) s.toasts.splice(0, s.toasts.length - 4);
  setTimeout(() => dismissToast(id), err ? 9000 : 4200);
}

// ---- WebSocket manager ---------------------------------------------------
// One socket at a time. Every handler checks it still belongs to the current
// socket, so a slow close from an old one can never schedule a second
// connection — the classic way a reconnect loop turns into two feeds and
// doubled counts. Backoff is jittered so a room of open consoles does not
// reconnect in lockstep when the daemon comes back.
let ws: WebSocket | null = null;
let backoff = 500;
let stopped = true;
let timer: ReturnType<typeof setTimeout> | undefined;
let onExpired: () => void = () => {};

function pushLive(ev: QueryEvent) {
  s.liveTotal++;
  if (s.paused) return;
  s.live.unshift(ev);
  if (s.live.length > LIVE_CAP) s.live.length = LIVE_CAP;
}

function schedule(delay: number) {
  clearTimeout(timer);
  timer = setTimeout(connect, delay);
}

/** A socket that never opened is either a daemon that is down or a session that
 *  ended — the browser reports both as the same bare close. Asking /auth/me
 *  tells them apart, so an expired session goes back to sign-in instead of
 *  retrying forever behind a "not answering" badge. */
async function sessionEnded(): Promise<boolean> {
  try {
    const r = await fetch("/api/v1/auth/me", { credentials: "include", headers: authHeader() });
    if (r.status === 401 || r.status === 403) return true;
    if (!r.ok) return false;
    const me = await r.json().catch(() => null);
    return !!me && !me.user;
  } catch { return false; }   // unreachable: the daemon is down, keep trying
}

function authHeader(): HeadersInit {
  const t = local.get("dg_token");
  return t ? { Authorization: "Bearer " + t } : {};
}

function connect() {
  clearTimeout(timer);
  if (stopped) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const sock = new WebSocket(`${proto}://${location.host}/api/v1/ws`);
  let opened = false;
  ws = sock;
  if (s.conn !== "reconnecting") s.conn = "connecting";
  sock.onopen = () => {
    if (ws !== sock) return;
    opened = true;
    backoff = 500;
    s.conn = "live";
  };
  sock.onmessage = (m) => {
    if (ws !== sock) return;
    let frame: any;
    try { frame = JSON.parse(m.data); } catch { return; }
    if (frame.type === "hello") {
      s.stats = frame.data.stats;
      s.series = frame.data.series || [];
      s.dropped = 0;
      // a paused tape is a promise that what is on screen stays put
      if (!s.paused) s.live = (frame.data.recent || []).slice(0, LIVE_CAP);
    } else if (frame.type === "query") {
      pushLive(frame.data);
    } else if (frame.type === "stats") {
      s.stats = frame.data;
      if (frame.series) s.series = frame.series;
      if (typeof frame.dropped === "number") s.dropped = frame.dropped;
    }
  };
  sock.onclose = async () => {
    if (ws !== sock || stopped) return;
    ws = null;
    s.conn = "reconnecting";
    if (!opened && await sessionEnded()) {
      if (stopped) return;
      store.stopWs();
      onExpired();
      return;
    }
    if (stopped || ws) return;
    schedule(backoff * (0.5 + Math.random() * 0.5));
    backoff = Math.min(backoff * 1.7, 8000);
  };
  sock.onerror = () => sock.close();
}

/** Come straight back when there is reason to think it will work — the tab is
 *  visible again or the network returned — rather than waiting out a backoff
 *  that grew while nobody was looking. */
function retryNow() {
  if (stopped || ws || document.visibilityState === "hidden") return;
  backoff = 500;
  connect();
}
if (typeof window !== "undefined") {
  document.addEventListener("visibilitychange", retryNow);
  window.addEventListener("online", retryNow);
}

export const store = {
  state: readonly(s) as unknown as typeof s,
  toast,
  dismissToast,
  setUser: (u: typeof s.user) => { s.user = u; },
  togglePause: () => { s.paused = !s.paused; },
  inspect: (kind: "domain" | "client", value: string) => { s.inspecting = { kind, value }; },
  closeInspector: () => { s.inspecting = null; },
  clearLive: () => { s.live = []; },
  /** What to do when the session is found to have ended (App.vue: sign-in). */
  onSessionExpired(f: () => void) { onExpired = f; },
  startWs() { stopped = false; if (!ws) { backoff = 500; connect(); } },
  stopWs() {
    stopped = true;
    clearTimeout(timer);
    const old = ws;
    ws = null;
    old?.close();
    s.conn = "offline";
  },
};
