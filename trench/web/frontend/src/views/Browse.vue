<script setup lang="ts">
/* The browser — the primary surface.
 *
 * A DNS console is a browser over one relation, and the only question that
 * matters is "grouped by what, then by what". So the screen is a chain of
 * facets: each column is one level of the grouping, picking a row narrows
 * everything to its right, and the operator chooses the order. `suffix → domain
 * → name` reads the namespace. `device → domain → name` reads the network.
 * `list → rule → name` reads your own policy back to you by its effect. One
 * mechanism, three questions, no separate screens for each.
 *
 * Columns rather than a tree or a treemap, for reasons that are not aesthetic:
 * a column always has room for a full identifier, so nothing is ever truncated
 * to an ellipsis; every level stays visible so you can see the path you took;
 * and it is trivially keyboard-navigable, which a treemap is not. A treemap
 * would have been faster to build and would have made every label unreadable.
 *
 * Time is deliberately not an axis here. It appears in one band, for the
 * current selection, because a time series of one thing is legible and forty at
 * once is texture.
 */
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "../lib/api";
import {
  aggregate, asQuery, FACETS, histogram, narrow, PLANS, SORTS, sortNodes,
  summarise, type FacetKey, type Node, type SortKey,
} from "../lib/facets";
import { align } from "../lib/dnsname";
import { store, type QueryEvent } from "../lib/store";
import {
  compile, evaluate, explain, pushdown, QueryError, reference,
  type Ctx, type Node as Ast, type Row,
} from "../lib/qlang";
import { registrable } from "../lib/dnsname";
import { copyText } from "../lib/util";
import Evidence from "../ui/Evidence.vue";
import Ico from "../ui/Ico.vue";
import Spine from "../ui/Spine.vue";
import Span from "../ui/Span.vue";

const route = useRoute();
const router = useRouter();
const nf = new Intl.NumberFormat();

/* ── the window ─────────────────────────────────────────────────────────────
 * Named spans rather than a date picker: an operator diagnosing something says
 * "the last hour", never "14:07 to 15:07". The picker exists for the rare case
 * and is not the default control. */
const WINDOWS = [
  { label: "15 min", us: 900e6 },
  { label: "1 hour", us: 3600e6 },
  { label: "6 hours", us: 6 * 3600e6 },
  { label: "24 hours", us: 24 * 3600e6 },
  { label: "7 days", us: 7 * 24 * 3600e6 },
];
const winIdx = ref(2);

const plan = ref<FacetKey[]>([...PLANS[0].keys]);
const picked = ref<(string | null)[]>([null, null, null]);
const sortBy = ref<SortKey>("volume");
const cursor = ref<[number, number]>([0, -1]);   // [column, row]

const rows = ref<Row[]>([]);
const total = ref(0);
const loading = ref(true);
const err = ref("");
const labels = ref<Record<string, string>>({});

const queryText = ref((route.query.q as string) || "");
const ast = ref<Ast>({ t: "all" });
const qErr = ref("");
const qBox = ref<HTMLInputElement | null>(null);

const menu = ref<"" | "plan" | "sort" | "window">("");
const showKeys = ref(false);
const showHud = ref(false);
const hud = ref({ ms: 0, rows: 0 });

const t1 = computed(() => Date.now() * 1000);
const t0 = computed(() => t1.value - WINDOWS[winIdx.value].us);

/* ── query language ──────────────────────────────────────────────────────── */
const qctx: Ctx = {
  registrable,
  clientsFor: (n) => clientsPerName.value.get(n) ?? 1,
  firstSeen: (n) => firstSeenPerName.value.get(n),
};
const clientsPerName = computed(() => {
  const m = new Map<string, Set<string>>();
  for (const r of rows.value) {
    const k = r.qname.toLowerCase();
    let s = m.get(k);
    if (!s) { s = new Set(); m.set(k, s); }
    s.add(r.client_ip);
  }
  return new Map([...m].map(([k, v]) => [k, v.size]));
});
const firstSeenPerName = computed(() => {
  const m = new Map<string, number>();
  for (const r of rows.value) {
    const k = r.qname.toLowerCase();
    const cur = m.get(k);
    if (cur === undefined || r.ts < cur) m.set(k, r.ts);
  }
  return m;
});

watch(queryText, (v) => {
  try { ast.value = compile(v); qErr.value = ""; }
  catch (e) { qErr.value = e instanceof QueryError ? e.message : String(e); }
}, { immediate: true });

const said = computed(() => (qErr.value ? "" : explain(ast.value)));
const kept = computed(() => {
  const t = performance.now();
  const out = qErr.value ? rows.value : rows.value.filter((r) => evaluate(ast.value, r, qctx));
  hud.value = { ms: Number((performance.now() - t).toFixed(1)), rows: rows.value.length };
  return out;
});

/* ── columns ─────────────────────────────────────────────────────────────── */
const columns = computed(() => {
  const out: { key: FacetKey; nodes: Node[]; max: number }[] = [];
  for (let i = 0; i < plan.value.length; i++) {
    const scope = narrow(kept.value, plan.value, picked.value.slice(0, i));
    const nodes = sortNodes(aggregate(scope, plan.value[i]), sortBy.value);
    out.push({ key: plan.value[i], nodes, max: Math.max(1, ...nodes.map((n) => n.total)) });
  }
  return out;
});

const selected = computed(() => narrow(kept.value, plan.value, picked.value));
const summary = computed(() => summarise(selected.value));
const buckets = computed(() => histogram(selected.value, t0.value, t1.value, 120));

const path = computed(() =>
  plan.value.map((k, i) => ({ label: FACETS[k].label, value: picked.value[i] || "" }))
    .filter((p) => p.value));

/* Reaching one query.
 *
 * The chain is the most valuable panel in the product, and in the first cut it
 * only appeared when a selection happened to contain exactly one row — which for
 * real traffic is almost never, so the panel was effectively unreachable. Once
 * the deepest level is picked the selection is a specific name, so the panel
 * shows one of its occurrences, newest first, with the rest a keystroke away.
 * Three clicks from the whole network to a single decision, always.
 */
const occurrences = computed(() =>
  picked.value[plan.value.length - 1]
    ? selected.value.slice().sort((a, b) => b.ts - a.ts)
    : selected.value.length === 1 ? selected.value : []);
const occIdx = ref(0);
watch(occurrences, () => { occIdx.value = 0; });
const one = computed(() => occurrences.value[occIdx.value] ?? null);
function stepOcc(d: number) {
  if (!occurrences.value.length) return;
  occIdx.value = (occIdx.value + d + occurrences.value.length) % occurrences.value.length;
}

function pick(col: number, value: string) {
  const next = picked.value.slice();
  next[col] = next[col] === value ? null : value;
  for (let i = col + 1; i < next.length; i++) next[i] = null;   // deeper picks are stale
  picked.value = next;
  cursor.value = [col, columns.value[col].nodes.findIndex((n) => n.value === value)];
  syncUrl();
}

function setPlan(keys: FacetKey[]) {
  plan.value = [...keys];
  picked.value = keys.map(() => null);
  menu.value = "";
  syncUrl();
}

function syncUrl() {
  router.replace({
    query: {
      ...route.query,
      q: queryText.value || undefined,
      p: plan.value.join(",") || undefined,
      s: picked.value.filter(Boolean).length ? picked.value.map((v) => v || "").join("|") : undefined,
      w: String(winIdx.value),
    },
  });
}

/* ── loading ─────────────────────────────────────────────────────────────────
 * The API caps a page at 1000 rows. A wide window is paged with a budget, and
 * when the budget runs out the interface says so rather than drawing a subset as
 * though it were the whole picture. */
const PAGE = 1000, BUDGET = 12;

async function load() {
  loading.value = true;
  err.value = "";
  const base = { ...pushdown(ast.value), since: t0.value, until: t1.value, limit: PAGE };
  const got: Row[] = [];
  try {
    for (let page = 0; page < BUDGET; page++) {
      const r = await api.get("/querylog" + api.qs({ ...base, offset: page * PAGE }));
      total.value = r.total ?? 0;
      got.push(...(r.rows || []));
      if (!r.rows || r.rows.length < PAGE) break;
    }
    rows.value = got;
  } catch (e: any) {
    err.value = e?.message || "the query log could not be read";
  } finally {
    loading.value = false;
  }
}
const shortfall = computed(() => Math.max(0, total.value - rows.value.length));

/* Live rows join the window on a timer, not on arrival.
 *
 * The columns are ranked by volume, so folding in one query re-sorts them: at a
 * few hundred queries a second the whole surface reshuffles continuously and
 * nothing can be read, let alone clicked. Batching to a slow tick keeps the view
 * live while leaving it still long enough to use. */
const FLUSH_MS = 2500;
let pending: Row[] = [];
let flushTimer: number | undefined;

watch(() => store.state.liveTotal, () => {
  const live = store.state.live;
  if (!live.length) return;
  const newest = rows.value.length ? Math.max(...rows.value.slice(-50).map((r) => r.ts)) : 0;
  const seen = pending.length ? Math.max(newest, ...pending.map((r) => r.ts)) : newest;
  const add = live.map((e: QueryEvent) => ({
    ts: e.ts > 1e12 ? e.ts : Math.round(e.ts * 1e6),
    client_ip: e.client, qname: e.domain, qtype: e.type, action: e.action,
    rcode: e.rcode, upstream: e.upstream, elapsed_us: e.elapsed_us, reason: e.reason,
    answers: "[]",
  } as Row)).filter((r) => r.ts > seen);
  if (!add.length) return;
  pending.push(...add);
  if (flushTimer === undefined) {
    flushTimer = window.setTimeout(() => {
      flushTimer = undefined;
      if (pending.length) { rows.value = [...rows.value, ...pending]; pending = []; }
    }, FLUSH_MS);
  }
});
onUnmounted(() => { if (flushTimer !== undefined) window.clearTimeout(flushTimer); });

/* ── keyboard: the columns are a Finder-style browser ───────────────────── */
function onKey(e: KeyboardEvent) {
  const tag = (e.target as HTMLElement)?.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA") {
    if (e.key === "Escape") (e.target as HTMLElement).blur();
    return;
  }
  const [c, r] = cursor.value;
  const col = columns.value[c];
  switch (e.key) {
    case "/": e.preventDefault(); qBox.value?.focus(); return;
    case "?": showKeys.value = !showKeys.value; return;
    case "j": case "ArrowDown":
      e.preventDefault();
      cursor.value = [c, Math.min((col?.nodes.length ?? 1) - 1, r + 1)]; return;
    case "k": case "ArrowUp":
      e.preventDefault(); cursor.value = [c, Math.max(0, r - 1)]; return;
    case "l": case "ArrowRight": case "Enter":
      e.preventDefault();
      if (col && col.nodes[r]) pick(c, col.nodes[r].value);
      if (c + 1 < plan.value.length) cursor.value = [c + 1, 0];
      return;
    case "h": case "ArrowLeft":
      e.preventDefault();
      if (c > 0) cursor.value = [c - 1, Math.max(0, picked.value[c - 1] ? r : 0)];
      return;
    case "Escape": picked.value = plan.value.map(() => null); syncUrl(); return;
    case "s": menu.value = menu.value === "sort" ? "" : "sort"; return;
    case "f": menu.value = menu.value === "plan" ? "" : "plan"; return;
    case "w": menu.value = menu.value === "window" ? "" : "window"; return;
    case "n": stepOcc(1); return;
    case "p": stepOcc(-1); return;
    case "y": copySelection(); return;
    case "F": showHud.value = !showHud.value; return;
  }
  if (e.key >= "1" && e.key <= "5") { winIdx.value = Number(e.key) - 1; load(); syncUrl(); }
}

function copySelection() {
  const q = asQuery(plan.value, picked.value);
  const lines = [
    `# ${nf.format(summary.value.total)} queries` + (q ? ` · ${q}` : ""),
    `# window ${new Date(t0.value / 1000).toISOString()} .. ${new Date(t1.value / 1000).toISOString()}`,
    "",
    ...columns.value[columns.value.length - 1].nodes.slice(0, 200).map((n) =>
      `${String(n.total).padStart(7)}  ${String(n.by.blocked).padStart(6)}↓  ${n.value}`),
  ];
  copyText(lines.join("\n"));
  store.toast("Copied", "the current column as text");
}

onMounted(() => {
  window.addEventListener("keydown", onKey);
  // restore a shared view
  const p = route.query.p as string | undefined;
  if (p) plan.value = p.split(",") as FacetKey[];
  const s = route.query.s as string | undefined;
  if (s) picked.value = s.split("|").map((v) => v || null);
  const w = route.query.w as string | undefined;
  if (w && Number(w) >= 0 && Number(w) < WINDOWS.length) winIdx.value = Number(w);

  api.get("/clients").then((d: any) => {
    const list = Array.isArray(d) ? d : d?.clients || d?.rows || [];
    const out: Record<string, string> = {};
    for (const c of list) {
      const ip = c.ip || c.client_ip || c.address || c.client;
      const nm = c.name || c.label || c.hostname || c.id;
      if (ip && nm && ip !== nm) out[String(ip)] = String(nm);
    }
    labels.value = out;
  }).catch(() => {});
  load();
});
onUnmounted(() => window.removeEventListener("keydown", onKey));

watch(queryText, () => { nextTick(syncUrl); });

/** A device row shows its name and its address; both are identifiers. */
function rowLabel(key: FacetKey, value: string) {
  if (key === "device") return { dim: labels.value[value] ? value + " " : "", main: labels.value[value] || value };
  if (key === "name" || key === "domain") {
    const a = align(value);
    return { dim: a.sub ? a.sub + "." : "", main: a.reg };
  }
  return { dim: "", main: value };
}

const planName = computed(() =>
  PLANS.find((p) => p.keys.join() === plan.value.join())?.name || "Custom");
</script>

<template>
  <div class="bw" @click="menu = ''">
    <!-- ── controls ─────────────────────────────────────────────────────── -->
    <div class="bw-ctl" @click.stop>
      <div style="position:relative">
        <button class="bw-pick" @click="menu = menu === 'plan' ? '' : 'plan'">
          <Ico name="levels" />
          <b>{{ planName }}</b>
          <Ico name="down" :size="13" />
        </button>
        <div class="bw-menu" v-if="menu === 'plan'" style="top:38px;left:0">
          <button v-for="p in PLANS" :key="p.name" :class="{ on: p.name === planName }"
                  @click="setPlan(p.keys)">
            <b>{{ p.name }}</b><em>{{ p.note }} — {{ p.keys.map(k => FACETS[k].label).join(" › ") }}</em>
          </button>
        </div>
      </div>

      <div style="position:relative">
        <button class="bw-pick" @click="menu = menu === 'sort' ? '' : 'sort'">
          <Ico name="sort" />
          <b>{{ SORTS.find(s => s.key === sortBy)!.label }}</b>
          <Ico name="down" :size="13" />
        </button>
        <div class="bw-menu" v-if="menu === 'sort'" style="top:38px;left:0">
          <button v-for="s in SORTS" :key="s.key" :class="{ on: s.key === sortBy }"
                  @click="sortBy = s.key; menu = ''">
            <b>{{ s.label }}</b><em>{{ s.of }}</em>
          </button>
        </div>
      </div>

      <!-- five options, so they are all on screen. A menu that hides five
           short words costs a click and shows less. -->
      <span class="seg">
        <button v-for="(w, i) in WINDOWS" :key="w.label" :class="{ on: i === winIdx }"
                :title="`press ${i + 1}`"
                @click="winIdx = i; load(); syncUrl()">{{ w.label }}</button>
      </span>

      <input ref="qBox" class="bw-q" :class="{ bad: qErr }" v-model="queryText"
             spellcheck="false" @keydown.enter="load()"
             placeholder="blocked and device=10.0.4.71 · type / to focus, ? for keys" />

      <button class="bw-pick" @click="copySelection" title="copy this column as text">
        <Ico name="copy" />
      </button>
    </div>

    <!-- ── the query, read back ─────────────────────────────────────────── -->
    <div class="bw-said" v-if="queryText">
      <span class="err" v-if="qErr">{{ qErr }}</span>
      <p v-else>{{ said }}</p>
      <span class="tail b-cap">{{ nf.format(kept.length) }} of {{ nf.format(rows.length) }} loaded</span>
    </div>
    <div class="b-warn" v-if="shortfall">
      Showing the {{ nf.format(rows.length) }} most recent of {{ nf.format(total) }} in this
      window. Narrow the window or the query to account for all of it.
    </div>
    <div class="b-warn" v-if="err">{{ err }}</div>

    <!-- ── columns + evidence ───────────────────────────────────────────── -->
    <div class="bw-cols">
      <section class="bw-col" v-for="(col, ci) in columns" :key="ci">
        <header class="bw-col-h">
          <h5 class="b-cap">{{ FACETS[col.key].label }}</h5>
          <span class="bw-col-n b-num">{{ nf.format(col.nodes.length) }}</span>
        </header>
        <div class="bw-rows">
          <div v-for="(n, ri) in col.nodes.slice(0, 400)" :key="n.value"
               class="bw-row"
               :class="{ on: picked[ci] === n.value, cursor: cursor[0] === ci && cursor[1] === ri }"
               @click="pick(ci, n.value)">
            <span class="bw-row-mk" v-if="n.authored" :title="`${n.authored} decided by your own rules`" />
            <span class="bw-row-v">
              <span class="dim">{{ rowLabel(col.key, n.value).dim }}</span>{{ rowLabel(col.key, n.value).main }}
            </span>
            <span class="bw-row-t b-num">{{ nf.format(n.total) }}</span>
            <span class="bw-row-sp">
              <Spine :by="n.by" :total="n.total" :max="col.max" />
            </span>
          </div>
          <p class="b-void-state" v-if="!col.nodes.length && !loading">
            <template v-if="ci === 0">
              No queries in the last {{ WINDOWS[winIdx].label.toLowerCase() }}<template v-if="queryText"> matching this query</template>.
            </template>
            <template v-else>
              Nothing to group here — pick something in <b>{{ FACETS[plan[ci - 1]].label }}</b> first.
            </template>
          </p>
          <p class="b-void-state" v-else-if="loading && !col.nodes.length">Reading the query log…</p>
        </div>
      </section>

      <Evidence :rows="kept" :summary="summary" :row="one" :path="path" :window-from="t0"
                :occurrence="occIdx" :occurrences="occurrences.length" @step="stepOcc"
                @query="(q) => { queryText = q; picked = plan.map(() => null); load(); }" />
    </div>

    <!-- ── when: the selection over time ────────────────────────────────── -->
    <div class="bw-span" v-if="summary.total">
      <div class="bw-span-h">
        <h5 class="b-cap">When</h5>
        <span class="b-cap">
          {{ path.length ? path.map(p => p.value).join(" › ") : "all traffic" }}
        </span>
        <span class="b-cap" style="margin-left:auto;display:flex;gap:14px;align-items:center">
          <span><i class="key" style="background:var(--o-cache)" />cached</span>
          <span><i class="key" style="background:var(--o-upstream)" />forwarded</span>
          <span><i class="key" style="background:var(--o-blocked)" />blocked</span>
          <span><i class="key" style="background:var(--o-failed)" />failed</span>
        </span>
      </div>
      <Span :buckets="buckets" :t0="t0" :t1="t1" :height="54" />
    </div>

    <!-- ── keys ─────────────────────────────────────────────────────────── -->
    <div class="keys" v-if="showKeys" @click.self="showKeys = false">
      <div class="keys-in">
        <h4 class="b-cap">Moving around</h4>
        <dl class="keys-tbl">
          <dt>j k ↑ ↓</dt><dd>move down and up a column</dd>
          <dt>l → enter</dt><dd>pick this row and step into the next column</dd>
          <dt>h ←</dt><dd>step back a column</dd>
          <dt>n p</dt><dd>step through the occurrences of a picked name</dd>
          <dt>esc</dt><dd>clear the whole selection</dd>
          <dt>1 – 5</dt><dd>window: 15 minutes to 7 days</dd>
        </dl>
        <h4 class="b-cap">Changing the question</h4>
        <dl class="keys-tbl">
          <dt>f</dt><dd>grouping order — <b>suffix › domain › name</b> reads the namespace, <b>device › domain › name</b> reads the network</dd>
          <dt>s</dt><dd>sort: the biggest row is often not the interesting one</dd>
          <dt>/</dt><dd>the query box</dd>
          <dt>y</dt><dd>copy the current column as text</dd>
          <dt>F</dt><dd>timings</dd>
        </dl>
        <h4 class="b-cap">Query language</h4>
        <dl class="keys-tbl">
          <template v-for="f in reference()" :key="f.name">
            <dt>{{ f.name }}</dt><dd>{{ f.help }}</dd>
          </template>
        </dl>
        <p class="b-read">
          Terms combine with <b>and</b>, <b>or</b>, <b>not</b> and parentheses;
          writing two terms next to each other means and. Values accept
          <b>*</b> and <b>?</b>, <b>=</b> for exact and <b>!=</b> for negation.
          Whatever the server can answer is pushed down to it and the rest is
          applied here, so the result is the same either way — only the amount
          fetched changes.
        </p>
      </div>
    </div>

    <div class="hud" v-if="showHud">
      filter {{ hud.ms }}ms · {{ nf.format(hud.rows) }} rows ·
      {{ columns.map(c => c.nodes.length).join("/") }} nodes
    </div>
  </div>
</template>
