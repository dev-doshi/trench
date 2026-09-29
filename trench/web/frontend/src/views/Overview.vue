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
import { nameOf, nameTitle, useNames } from "../lib/names";
import { KINDS, fillVar, kindOf, meta, type Kind } from "../lib/outcome";
import { term, type Row } from "../lib/qlang";
import Bars from "../ui/Bars.vue";
import Donut from "../ui/Donut.vue";
import Spark from "../ui/Spark.vue";
import Trend from "../ui/Trend.vue";

const RANGES = [{ hours: 24, label: "24 hours" }, { hours: 168, label: "7 days" }];
/* Colour means an outcome and nothing else. Anything that is not one is drawn
 * in a single ink and labelled where it is drawn, never told apart by shade:
 * greys a step apart cannot be matched to a legend. */
const LINE = "var(--b-ink-2)";
const TOP = 6;
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
useNames();
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
      an({ group: "qtype", top: TOP }),
      an({ group: "upstream", top: TOP + 1 }),
      an({ bucket: "hour", group: "client_ip", top: TOP }),
      an({ group: "qname", top: 10 }),
      an({ group: "qname", action: "blocked", top: 10 }),
      an({ group: "client_ip", top: 10 }),
      api.get("/stats"),
    ]);
    if (mine !== seq) return;           // a newer range was asked for meanwhile
    const [h, lat, latAll, qt, up, act, n, b, d, st] = r;
    hourly.value = h.series || [];
    latency.value = lat.series?.[0]?.points || [];
    latencyAll.value = latAll.rows?.[0]?.[1] ?? null;
    qtypes.value = qt.rows || [];
    // an empty upstream is a cache hit, a block or a local answer
    upstreams.value = (up.rows || []).filter((x: [string, number]) => x[0]).slice(0, TOP);
    activity.value = act.series || [];
    names.value = n.rows || [];
    blocked.value = b.rows || [];
    devices.value = d.rows || [];
    stats.value = st;
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
// tab should cost the Pi nothing. A tick that finds the last load still
// running skips, rather than queueing a second one behind it.
let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  load();
  timer = setInterval(() => { if (!document.hidden && !loading.value) load(); }, 60_000);
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
const who = nameOf;
/* Small multiples, not overlaid lines: one row per device, each its own line
 * on a shared scale, so the name sits beside the shape it belongs to. */
const activityRows = computed(() => {
  const rows = activity.value.map((g) => {
    const at = new Map(g.points);
    const values = times.value.map((t) => at.get(t) ?? 0);
    return { ip: g.group, values, total: sum(values), peak: Math.max(0, ...values) };
  });
  const top = Math.max(1, ...rows.map((r) => r.peak));
  return rows.map((r) => ({ ...r, top }));
});
const latencySeries = computed(() => latency.value.length
  ? [{ name: "avg ms", colour: LINE, points: latency.value }] : []);

const figures = computed(() => {
  const by = byKind.value;
  const cacheRate = times.value.map((_, i) =>
    perHour.value[i] ? ((by.get("cache")?.[i] ?? 0) / perHour.value[i]) * 100 : 0);
  return [
    { label: "Queries", value: nf.format(totals.value.all), unit: "",
      sub: `${nf.format(Math.round(totals.value.all / hours.value))} an hour on average`,
      colour: LINE, spark: perHour.value },
    { label: "Blocked", value: nf.format(totals.value.by.blocked), unit: share(totals.value.by.blocked),
      sub: "of all queries", colour: fillVar("blocked"), spark: by.get("blocked") ?? [] },
    { label: "Answered from cache", value: share(totals.value.by.cache), unit: "",
      sub: `${nf.format(totals.value.by.cache)} never left this box`,
      colour: fillVar("cache"), spark: cacheRate },
    { label: "Average response", value: latencyAll.value === null ? "—" : String(latencyAll.value), unit: "ms",
      sub: totals.value.by.failed ? `${nf.format(totals.value.by.failed)} failed` : "none failed",
      colour: LINE, spark: latency.value.map((p) => p[1]) },
  ];
});

const browse = (field: string, value: string) =>
  ({ path: "/browse", query: { q: term(field, value.replace(/\.$/, "").toLowerCase()) } });
const width = (v: number, rows: Ranked) => `${(v / Math.max(1, rows[0]?.[1] || 1)) * 100}%`;
const label = (n: string) => n.replace(/\.$/, "");
const clock = computed(() => updated.value?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
</script>

<template>
  <div class="vw ov">
    <header class="vw-head">
      <h2>Overview</h2>
      <span class="ov-sub" v-if="clock">updated {{ clock }}</span>
      <div class="acts">
        <span class="ov-state b-cap" v-if="stats" :class="{ off: !stats.enabled }"
              :title="`Trench ${stats.version}`">
          <i />{{ stats.enabled ? "filtering" : "filtering paused" }}
          <em>· {{ nf.format(stats.blocklist_size) }} names listed</em>
        </span>
        <div class="seg ov-seg" role="group" aria-label="Time range">
          <button v-for="r in RANGES" :key="r.hours" :class="{ on: hours === r.hours }"
                  :aria-pressed="hours === r.hours" @click="pick(r.hours)">{{ r.label }}</button>
        </div>
      </div>
    </header>

    <div class="vw-body">
      <p class="b-warn" v-if="err">{{ err }}</p>

      <!-- four figures, divided by hairlines: not tiles -->
      <div class="sec ov-figs">
        <div class="ov-fig" v-for="c in figures" :key="c.label">
          <h5 class="b-cap">{{ c.label }}</h5>
          <div class="ev-big">
            <b>{{ loading && !updated ? "—" : c.value }}</b><span v-if="c.unit">{{ c.unit }}</span>
          </div>
          <span class="ov-sub">{{ c.sub }}</span>
          <Spark :values="c.spark" :colour="c.colour" />
        </div>
      </div>

      <div class="sec">
        <div class="sec-h"><h5 class="b-cap">Queries over time</h5><span class="b-cap ov-note">per hour, by outcome</span></div>
        <Bars v-if="times.length && totals.all" :times="times" :stacks="stacks" :height="240" />
        <p class="b-void-state" v-else>{{ loading ? "Reading the query log…" : "Nothing logged in this span." }}</p>
      </div>

      <div class="sec cols ov-cols">
        <div>
          <div class="sec-h"><h5 class="b-cap">Outcomes</h5></div>
          <Donut v-if="outcomeParts.length" :parts="outcomeParts" unit="queries" />
          <p class="b-void-state" v-else>—</p>
        </div>
        <div>
          <div class="sec-h"><h5 class="b-cap">Record types</h5><span class="b-cap ov-note">most asked for</span></div>
          <table class="tb ov-tb" v-if="qtypes.length">
            <tbody>
              <tr v-for="[t, v] in qtypes" :key="t">
                <td class="id"><RouterLink :to="browse('type', t)" class="lnk">{{ t }}</RouterLink></td>
                <td class="ov-m"><div class="mtr"><i :style="{ width: width(v, qtypes), background: LINE }" /></div></td>
                <td class="r">{{ nf.format(v) }}</td>
                <td class="r ov-pct">{{ share(v) }}</td>
              </tr>
            </tbody>
          </table>
          <p class="b-void-state" v-else>—</p>
        </div>
        <div>
          <div class="sec-h"><h5 class="b-cap">Upstreams</h5><span class="b-cap ov-note">share of forwarded</span></div>
          <table class="tb ov-tb" v-if="upstreams.length">
            <tbody>
              <tr v-for="[u, v] in upstreams" :key="u">
                <td class="id" :title="u">{{ u }}</td>
                <td class="ov-m"><div class="mtr"><i :style="{ width: width(v, upstreams), background: 'var(--o-upstream)' }" /></div></td>
                <td class="r">{{ nf.format(v) }}</td>
                <td class="r ov-pct">{{ share(v, sum(upstreams.map((x) => x[1]))) }}</td>
              </tr>
            </tbody>
          </table>
          <p class="b-void-state" v-else>Nothing forwarded in this span.</p>
        </div>
      </div>

      <div class="sec cols ov-cols">
        <div>
          <div class="sec-h"><h5 class="b-cap">Device activity</h5><span class="b-cap ov-note">per hour, one scale</span></div>
          <table class="tb ov-tb ov-mult" v-if="activityRows.length">
            <tbody>
              <tr v-for="r in activityRows" :key="r.ip">
                <td class="id"><RouterLink :to="browse('client', r.ip)" class="lnk" :title="nameTitle(r.ip)">{{ who(r.ip) || r.ip }}</RouterLink></td>
                <td class="ov-sp"><Spark :values="r.values" :colour="LINE" :max="r.top" /></td>
                <td class="r">{{ nf.format(r.total) }}</td>
              </tr>
            </tbody>
          </table>
          <p class="b-void-state" v-else>—</p>
        </div>
        <div>
          <div class="sec-h"><h5 class="b-cap">Response time</h5><span class="b-cap ov-note">average per hour</span></div>
          <Trend v-if="latencySeries.length" :series="latencySeries" :height="200" />
          <p class="b-void-state" v-else>—</p>
        </div>
      </div>

      <div class="sec cols ov-cols">
        <div>
          <div class="sec-h"><h5 class="b-cap">Top names</h5><span class="b-cap ov-note">share of all</span></div>
          <table class="tb ov-tb">
            <tbody>
              <tr v-for="[n, v] in names" :key="n">
                <td class="id"><RouterLink :to="browse('name', n)" class="lnk" :title="label(n)">{{ label(n) }}</RouterLink></td>
                <td class="ov-m"><div class="mtr"><i :style="{ width: width(v, names), background: 'var(--b-ink-3)' }" /></div></td>
                <td class="r">{{ nf.format(v) }}</td>
                <td class="r ov-pct">{{ share(v) }}</td>
              </tr>
            </tbody>
          </table>
          <p class="b-void-state" v-if="!names.length && !loading">Nothing logged in this span.</p>
        </div>
        <div>
          <div class="sec-h"><h5 class="b-cap">Top blocked</h5><span class="b-cap ov-note">share of blocked</span></div>
          <table class="tb ov-tb" v-if="blocked.length">
            <tbody>
              <tr v-for="[n, v] in blocked" :key="n">
                <td class="id"><RouterLink :to="browse('name', n)" class="lnk" :title="label(n)">{{ label(n) }}</RouterLink></td>
                <td class="ov-m"><div class="mtr"><i :style="{ width: width(v, blocked), background: 'var(--o-blocked)' }" /></div></td>
                <td class="r">{{ nf.format(v) }}</td>
                <td class="r ov-pct">{{ share(v, totals.by.blocked) }}</td>
              </tr>
            </tbody>
          </table>
          <p class="b-void-state" v-else-if="!loading">Nothing blocked in this span.</p>
        </div>
        <div>
          <div class="sec-h"><h5 class="b-cap">Top devices</h5><span class="b-cap ov-note">share of all</span></div>
          <table class="tb ov-tb">
            <tbody>
              <tr v-for="[ip, v] in devices" :key="ip">
                <td class="id"><RouterLink :to="browse('client', ip)" class="lnk" :title="nameTitle(ip)">{{ who(ip) || ip }}</RouterLink></td>
                <td class="ov-m"><div class="mtr"><i :style="{ width: width(v, devices), background: 'var(--b-ink-3)' }" /></div></td>
                <td class="r">{{ nf.format(v) }}</td>
                <td class="r ov-pct">{{ share(v) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<style>
/* Same furniture as every other view: ruled sections on one plane, the space
 * scale, no boxes. Only what that furniture lacks is defined here. */
.ov-note { color: var(--b-ink-4); }

/* four across, or two by two on a phone; a hairline only between neighbours */
.ov-figs { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); row-gap: var(--b-5); }
.ov-fig { display: grid; gap: var(--b-1); padding: 0 var(--b-4); min-width: 0;
  border-left: 1px solid var(--b-edge-soft); }
.ov-fig:first-child { padding-left: 0; border-left: 0; }
@media (max-width: 720px) {
  .ov-figs { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-fig:nth-child(odd) { padding-left: 0; border-left: 0; }
}
.ov-fig h5 { margin: 0; }
.ov-sub { font: 500 var(--b-cap)/1.4 var(--b-ui); color: var(--b-ink-4); }
.ov-fig .spk { margin-top: var(--b-1); height: 28px; }

.ov-cols { grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); }
.ov-cols > div { min-width: 0; container-type: inline-size; }
.ov-cols .sec-h { flex-wrap: wrap; row-gap: var(--b-1); }
.ov-cols .sec-h > * { white-space: nowrap; }

.ov-state { display: inline-flex; align-items: center; gap: var(--b-2); white-space: nowrap; color: var(--o-ok); }
.ov-state i { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.ov-state.off { color: var(--o-failed); }
.ov-state em { font-style: normal; color: var(--b-ink-4); }
.ov-seg button { padding: 6px 12px; }
@media (max-width: 720px) { .ov-state em { display: none; } }

.tb.ov-tb { table-layout: fixed; min-width: 0; }
.ov-mult td.ov-sp { width: 50%; padding-top: 3px; padding-bottom: 3px; vertical-align: middle; }
.ov-mult .spk { height: 22px; }  /* four columns fold; the 560px floor is for wider tables */
.ov-tb td:first-child { padding-left: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ov-tb td.ov-m { width: 18%; }
/* In a narrow card the name is the point and the bar only repeats the count
   beside it, so the bar gives its width to the name rather than cutting it. */
@container (max-width: 380px) { .ov-tb td.ov-m { display: none; } }
.ov-tb td.r { width: 56px; }
.ov-tb td.ov-pct { width: 44px; padding-right: 0; color: var(--b-ink-4); font-size: var(--b-cap); }
.ov-tb .lnk { color: var(--b-ink); }
</style>
