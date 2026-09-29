<script setup lang="ts">
/* Overview — the front page, in the shape Pi-hole and Technitium taught people
 * to expect: headline figures, traffic over time, what it was made of, and who
 * and what was busiest.
 *
 * Everything is read from the persisted query log through /analytics, so the
 * page survives a restart and agrees with History and Browse; the in-memory
 * counters restart at zero and would disagree with both. Every name and device
 * links into Browse, which is where "why" gets asked.
 */
import { computed, onMounted, onUnmounted, ref } from "vue";
import { api } from "../lib/api";
import { KINDS, fillVar, kindOf, meta, type Kind } from "../lib/outcome";
import { term, type Row } from "../lib/qlang";
import Bars from "../ui/Bars.vue";
import Donut from "../ui/Donut.vue";
import Spark from "../ui/Spark.vue";
import Trend from "../ui/Trend.vue";

const RANGES = [{ hours: 24, label: "24 hours" }, { hours: 168, label: "7 days" }];
const PALETTE = ["var(--o-upstream)", "var(--o-cache)", "var(--o-local)", "var(--o-failed)",
  "#5fb3c4", "#c98a6b", "var(--b-ink-4)", "var(--o-blocked)"];
const nf = new Intl.NumberFormat();

type Ranked = [string, number][];
type Points = [number, number][];
interface Grouped { group: string; points: Points }

const hours = ref(24);
const hourly = ref<Grouped[]>([]);
const latency = ref<Points>([]);
const latencyAll = ref<number | null>(null);
const qtypes = ref<Ranked>([]);
const upstreams = ref<Ranked>([]);
const activity = ref<Grouped[]>([]);
const names = ref<Ranked>([]);
const blocked = ref<Ranked>([]);
const devices = ref<Ranked>([]);
const deviceNames = ref<Map<string, string>>(new Map());
const stats = ref<{ enabled: boolean; blocklist_size: number; version: string } | null>(null);
const span = ref({ since: 0, until: 0 });
const loading = ref(true);
const updated = ref<Date | null>(null);
const err = ref("");

let seq = 0;
async function load() {
  const mine = ++seq;
  const until = Date.now() * 1000;
  const since = until - hours.value * 3600e6;
  const an = (p: Record<string, unknown>) =>
    api.get("/analytics" + api.qs({ since, until, bucket: "none", ...p }));
  loading.value = true;
  try {
    const r = await Promise.all([
      an({ bucket: "hour", group: "action", top: 12 }),
      an({ bucket: "hour", metric: "avg_latency" }),
      an({ metric: "avg_latency" }),
      an({ group: "qtype", top: 7 }),
      an({ group: "upstream", top: 7 }),
      an({ bucket: "hour", group: "client_ip", top: 5 }),
      an({ group: "qname", top: 10 }),
      an({ group: "qname", action: "blocked", top: 10 }),
      an({ group: "client_ip", top: 10 }),
      api.get("/stats"),
      api.get("/clients/manage").catch(() => ({ clients: [] })),
    ]);
    if (mine !== seq) return;           // a newer range was asked for meanwhile
    const [h, lat, latAll, qt, up, act, n, b, d, st, cl] = r;
    hourly.value = h.series || [];
    latency.value = lat.series?.[0]?.points || [];
    latencyAll.value = latAll.rows?.[0]?.[1] ?? null;
    qtypes.value = qt.rows || [];
    // an empty upstream is a cache hit, a block or a local answer
    upstreams.value = (up.rows || []).filter((x: [string, number]) => x[0]);
    activity.value = act.series || [];
    names.value = n.rows || [];
    blocked.value = b.rows || [];
    devices.value = d.rows || [];
    stats.value = st;
    deviceNames.value = new Map((cl.clients || [])
      .filter((x: any) => x.name && x.ident)
      .map((x: any) => [String(x.ident).toLowerCase(), x.name]));
    span.value = { since, until };
    updated.value = new Date();
    err.value = "";
  } catch (e: any) {
    if (mine === seq) err.value = e?.message || "the query log could not be read";
  } finally {
    if (mine === seq) loading.value = false;
  }
}

function pick(h: number) {
  if (h === hours.value) return;
  hours.value = h;
  load();
}

// Refresh once a minute while visible: the buckets are hourly, and a hidden
// tab should cost the Pi nothing.
let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 60_000);
});
onUnmounted(() => clearInterval(timer));

/* ── derived ─────────────────────────────────────────────────────────────── */

/* The log records actions; the console speaks in outcomes. Fold one into the
 * other with the same function every other view uses. */
const kind = (action: string): Kind => kindOf({ action, rcode: "" } as Row);
const colourOf = (k: Kind) => k === "unknown" ? "var(--b-ink-4)" : fillVar(k);

/** Every hour in the window, so a quiet hour draws as zero rather than a gap. */
const times = computed(() => {
  const { since, until } = span.value;
  const out: number[] = [];
  if (!until) return out;
  for (let t = Math.floor(since / 3600e6) * 3600; t <= until / 1e6; t += 3600) out.push(t);
  return out;
});

const byKind = computed(() => {
  const index = new Map(times.value.map((t, i) => [t, i]));
  const m = new Map<Kind, number[]>();
  for (const g of hourly.value) {
    const k = kind(g.group);
    const row = m.get(k) ?? new Array(times.value.length).fill(0);
    for (const [t, v] of g.points) {
      const i = index.get(t);
      if (i !== undefined) row[i] += v;
    }
    m.set(k, row);
  }
  return m;
});
const sum = (a: number[]) => a.reduce((x, y) => x + y, 0);
const perHour = computed(() => times.value.map((_, i) =>
  [...byKind.value.values()].reduce((a, row) => a + row[i], 0)));
const totals = computed(() => {
  const by = Object.fromEntries(KINDS.map((k) => [k, sum(byKind.value.get(k) ?? [])])) as Record<Kind, number>;
  return { by, all: sum(perHour.value) };
});
const share = (n: number, of = totals.value.all) => {
  if (!of) return "—";
  const p = (n / of) * 100;
  return `${p >= 10 ? Math.round(p) : p.toFixed(1)}%`;
};

const stacks = computed(() => KINDS.filter((k) => byKind.value.has(k)).map((k) => ({
  name: meta(k).label, colour: colourOf(k), values: byKind.value.get(k)!,
})));
const outcomeParts = computed(() => KINDS.filter((k) => totals.value.by[k]).map((k) => ({
  name: meta(k).label, value: totals.value.by[k], colour: colourOf(k),
})));
const ranked = (rows: Ranked) => rows.map(([name, value], i) =>
  ({ name, value, colour: PALETTE[i % PALETTE.length] }));

const who = (ip: string) => deviceNames.value.get(ip.toLowerCase()) || "";
const activitySeries = computed(() => activity.value.map((g, i) => ({
  name: who(g.group) || g.group, colour: PALETTE[i % PALETTE.length],
  points: times.value.map((t) => [t, g.points.find((p) => p[0] === t)?.[1] ?? 0] as [number, number]),
})));
const latencySeries = computed(() => latency.value.length
  ? [{ name: "avg ms", colour: "var(--o-upstream)", points: latency.value }] : []);

const cards = computed(() => {
  const by = byKind.value;
  const cacheRate = times.value.map((_, i) =>
    perHour.value[i] ? ((by.get("cache")?.[i] ?? 0) / perHour.value[i]) * 100 : 0);
  return [
    { label: "Total queries", value: nf.format(totals.value.all),
      sub: `${nf.format(Math.round(totals.value.all / hours.value))} per hour on average`,
      colour: "var(--o-upstream)", spark: perHour.value },
    { label: "Blocked", value: nf.format(totals.value.by.blocked),
      sub: `${share(totals.value.by.blocked)} of all queries`,
      colour: "var(--o-blocked)", spark: by.get("blocked") ?? [] },
    { label: "Answered from cache", value: share(totals.value.by.cache),
      sub: `${nf.format(totals.value.by.cache)} without leaving this box`,
      colour: "var(--o-cache)", spark: cacheRate },
    { label: "Average response", value: latencyAll.value === null ? "—" : `${latencyAll.value} ms`,
      sub: totals.value.by.failed ? `${nf.format(totals.value.by.failed)} failed` : "no failed lookups",
      colour: "var(--o-local)", spark: latency.value.map((p) => p[1]) },
  ];
});

const browse = (field: string, value: string) =>
  ({ path: "/browse", query: { q: term(field, value.replace(/\.$/, "").toLowerCase()) } });
const width = (v: number, rows: Ranked) => `${(v / Math.max(1, rows[0]?.[1] || 1)) * 100}%`;
const clock = computed(() => updated.value?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
</script>

<template>
  <div class="vw ov">
    <header class="vw-head">
      <h2>Overview</h2>
      <p v-if="clock">Updated {{ clock }}</p>
      <div class="acts">
        <span class="ov-state" v-if="stats" :class="{ off: !stats.enabled }"
              :title="`Trench ${stats.version}`">
          <i />{{ stats.enabled ? "Filtering on" : "Filtering paused" }}
          <em>{{ nf.format(stats.blocklist_size) }} domains on the lists</em>
        </span>
        <div class="ov-seg" role="group" aria-label="Time range">
          <button v-for="r in RANGES" :key="r.hours" :class="{ on: hours === r.hours }"
                  :aria-pressed="hours === r.hours" @click="pick(r.hours)">{{ r.label }}</button>
        </div>
      </div>
    </header>

    <div class="vw-body">
      <p class="b-warn" v-if="err">{{ err }}</p>

      <div class="ov-grid ov-cards">
        <div class="ov-card ov-stat" v-for="c in cards" :key="c.label" :style="{ '--ac': c.colour }">
          <span class="ov-k">{{ c.label }}</span>
          <b class="ov-v">{{ loading && !updated ? "—" : c.value }}</b>
          <span class="ov-s">{{ c.sub }}</span>
          <Spark :values="c.spark" :colour="c.colour" />
        </div>
      </div>

      <section class="ov-card">
        <header class="ov-h">
          <h3>Queries over time</h3>
          <span>per hour, by outcome</span>
        </header>
        <Bars v-if="times.length && totals.all" :times="times" :stacks="stacks" :height="250" />
        <p class="ov-empty" v-else>{{ loading ? "Reading the query log…" : "Nothing logged in this span." }}</p>
      </section>

      <div class="ov-grid ov-thirds">
        <section class="ov-card">
          <header class="ov-h"><h3>Outcomes</h3><span>what happened to each query</span></header>
          <Donut v-if="outcomeParts.length" :parts="outcomeParts" unit="queries" />
          <p class="ov-empty" v-else>—</p>
        </section>
        <section class="ov-card">
          <header class="ov-h"><h3>Record types</h3><span>the most asked for</span></header>
          <Donut v-if="qtypes.length" :parts="ranked(qtypes)" unit="queries" />
          <p class="ov-empty" v-else>—</p>
        </section>
        <section class="ov-card">
          <header class="ov-h"><h3>Upstreams</h3><span>queries that left this box</span></header>
          <Donut v-if="upstreams.length" :parts="ranked(upstreams)" unit="forwarded" />
          <p class="ov-empty" v-else>Nothing forwarded in this span.</p>
        </section>
      </div>

      <div class="ov-grid ov-halves">
        <section class="ov-card">
          <header class="ov-h"><h3>Device activity</h3><span>queries per hour, busiest five</span></header>
          <Trend v-if="activitySeries.length" :series="activitySeries" :height="200" />
          <p class="ov-empty" v-else>—</p>
        </section>
        <section class="ov-card">
          <header class="ov-h"><h3>Response time</h3><span>average per hour, cache hits included</span></header>
          <Trend v-if="latencySeries.length" :series="latencySeries" :height="200" />
          <p class="ov-empty" v-else>—</p>
        </section>
      </div>

      <div class="ov-grid ov-thirds">
        <section class="ov-card">
          <header class="ov-h"><h3>Top domains</h3><span>share of all queries</span></header>
          <ol class="ov-list">
            <li v-for="[n, v] in names" :key="n">
              <RouterLink :to="browse('name', n)" class="ov-name" :title="n">{{ n.replace(/\.$/, "") }}</RouterLink>
              <span class="ov-num">{{ nf.format(v) }}</span>
              <span class="ov-pct">{{ share(v) }}</span>
              <span class="ov-track"><i :style="{ width: width(v, names) }" /></span>
            </li>
          </ol>
        </section>
        <section class="ov-card">
          <header class="ov-h"><h3>Top blocked</h3><span>share of blocked queries</span></header>
          <ol class="ov-list" v-if="blocked.length">
            <li v-for="[n, v] in blocked" :key="n">
              <RouterLink :to="browse('name', n)" class="ov-name" :title="n">{{ n.replace(/\.$/, "") }}</RouterLink>
              <span class="ov-num">{{ nf.format(v) }}</span>
              <span class="ov-pct">{{ share(v, totals.by.blocked) }}</span>
              <span class="ov-track"><i class="blocked" :style="{ width: width(v, blocked) }" /></span>
            </li>
          </ol>
          <p class="ov-empty" v-else-if="!loading">Nothing blocked in this span.</p>
        </section>
        <section class="ov-card">
          <header class="ov-h"><h3>Top devices</h3><span>share of all queries</span></header>
          <ol class="ov-list">
            <li v-for="[ip, v] in devices" :key="ip">
              <RouterLink :to="browse('client', ip)" class="ov-name" :title="ip">
                {{ who(ip) || ip }}<small v-if="who(ip)">{{ ip }}</small>
              </RouterLink>
              <span class="ov-num">{{ nf.format(v) }}</span>
              <span class="ov-pct">{{ share(v) }}</span>
              <span class="ov-track"><i class="device" :style="{ width: width(v, devices) }" /></span>
            </li>
          </ol>
        </section>
      </div>
    </div>
  </div>
</template>

<style>
.ov .vw-body { padding-top: var(--b-5); display: grid; gap: var(--b-4); }
.ov-grid { display: grid; gap: var(--b-4); }
.ov-cards { grid-template-columns: repeat(auto-fit, minmax(min(100%, 150px), 1fr)); }
.ov-thirds { grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); }
.ov-halves { grid-template-columns: repeat(auto-fit, minmax(min(100%, 440px), 1fr)); }

.ov-card {
  background: var(--b-sunk); border: 1px solid var(--b-edge-soft); border-radius: 10px;
  padding: 16px 18px; min-width: 0;
}
.ov-h { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
.ov-h h3 { margin: 0; font: 600 14px/1.2 var(--b-ui); color: var(--b-ink); }
.ov-h span { font: 500 var(--b-cap)/1.2 var(--b-ui); color: var(--b-ink-4); }
.ov-empty { margin: 0; padding: 28px 0; text-align: center;
  font: 400 var(--b-ui-s)/1.5 var(--b-ui); color: var(--b-ink-4); }

/* headline figures: a coloured rule, the figure, what it means, its shape */
.ov-stat { display: flex; flex-direction: column; gap: 4px; padding-bottom: 12px;
  border-top: 3px solid var(--ac); }
.ov-k { font: 600 var(--b-cap)/1.2 var(--b-ui); letter-spacing: .06em; text-transform: uppercase;
  color: var(--b-ink-3); }
.ov-v { font: 650 28px/1.15 var(--b-ui); color: var(--b-ink); letter-spacing: -.02em;
  font-variant-numeric: tabular-nums; margin-top: 4px; }
.ov-s { font: 500 var(--b-cap)/1.3 var(--b-ui); color: var(--b-ink-4); margin-bottom: 6px; }
.ov-stat .spk { margin-top: auto; }
.ov-state { display: inline-flex; align-items: center; gap: 7px; white-space: nowrap;
  font: 600 var(--b-ui-s)/1 var(--b-ui); color: var(--o-ok); }
.ov-state i { width: 8px; height: 8px; border-radius: 50%; background: currentColor;
  box-shadow: 0 0 0 3px color-mix(in srgb, currentColor 22%, transparent); }
.ov-state.off { color: var(--o-failed); }
.ov-state em { font: 500 var(--b-cap)/1 var(--b-ui); font-style: normal; color: var(--b-ink-4); }
@media (max-width: 720px) { .ov-state em { display: none; } }

/* the range switch */
.ov-seg { display: inline-flex; border: 1px solid var(--b-edge); border-radius: 7px; padding: 2px; }
.ov-seg button { background: none; border: 0; border-radius: 5px; padding: 6px 12px; cursor: pointer;
  font: 500 var(--b-ui-s)/1 var(--b-ui); color: var(--b-ink-3); }
.ov-seg button:hover { color: var(--b-ink); }
.ov-seg button.on { background: var(--b-pick); color: var(--b-ink); }

/* ranked lists: name, count, share, and a bar against the leader */
.ov-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 9px; }
.ov-list li { display: grid; grid-template-columns: minmax(0, 1fr) auto 46px; align-items: baseline;
  column-gap: 12px; row-gap: 4px; }
.ov-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-decoration: none;
  font: 400 var(--b-id-s)/1.3 var(--b-id); color: var(--b-ink); }
.ov-name:hover { text-decoration: underline; text-underline-offset: 3px; }
.ov-name small { margin-left: 8px; color: var(--b-ink-4); font-size: var(--b-cap); }
.ov-num { font: 600 var(--b-ui-s)/1 var(--b-ui); color: var(--b-ink-2); font-variant-numeric: tabular-nums; }
.ov-pct { text-align: right; font: 500 var(--b-cap)/1 var(--b-ui); color: var(--b-ink-4);
  font-variant-numeric: tabular-nums; }
.ov-track { grid-column: 1 / -1; height: 4px; border-radius: 2px; background: var(--b-edge-soft);
  overflow: hidden; }
.ov-track i { display: block; height: 100%; border-radius: 2px; background: var(--o-upstream); }
.ov-track i.blocked { background: var(--o-blocked); }
.ov-track i.device { background: var(--o-local); }
</style>
