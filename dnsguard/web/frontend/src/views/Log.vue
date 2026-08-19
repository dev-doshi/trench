<script setup lang="ts">
/* Log — flat rows, for when a table is the right tool.
 *
 * Browse answers "what is my network asking for". This answers "show me the
 * actual records, in order, so I can read or export them". Both are needed and
 * pretending one replaces the other is how tools end up with a beautiful
 * dashboard and a useless grep.
 *
 * Decisions:
 *   · the same query language as Browse. A second, different filter syntax in
 *     the same product is a tax on the operator's memory
 *   · what the server can answer is pushed down to it; the rest is applied here.
 *     The row count states both numbers so it is clear which is which
 *   · time is relative in the column and absolute in the title attribute:
 *     "40s ago" is what you want when reading, the timestamp is what you want
 *     when quoting
 *   · a row expands *in place* into its chain. A drawer would cover the rows you
 *     are comparing it against
 *   · export is NDJSON as well as CSV, because these rows are events and a
 *     stream of objects survives a name containing a comma
 */
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "../lib/api";
import { align, answerList } from "../lib/dnsname";
import { isAuthored, isStale, kindOf, meta, outcomeOf } from "../lib/outcome";
import {
  compile, evaluate, explain, pushdown, QueryError, type Ctx, type Node, type Row,
} from "../lib/qlang";
import { registrable } from "../lib/dnsname";
import { store } from "../lib/store";
import { download, toCsv } from "../lib/util";
import Ico from "../ui/Ico.vue";

const route = useRoute();
const router = useRouter();
const nf = new Intl.NumberFormat();

const WINDOWS = [
  { label: "1 hour", us: 3600e6 }, { label: "6 hours", us: 6 * 3600e6 },
  { label: "24 hours", us: 24 * 3600e6 }, { label: "7 days", us: 7 * 24 * 3600e6 },
];
const winIdx = ref(1);
const rows = ref<Row[]>([]);
const total = ref(0);
const loading = ref(true);
const err = ref("");
const open = ref<number | null>(null);
const follow = ref(false);

const queryText = ref((route.query.q as string) || "");
const ast = ref<Node>({ t: "all" });
const qErr = ref("");

const qctx: Ctx = { registrable };
watch(queryText, (v) => {
  try { ast.value = compile(v); qErr.value = ""; }
  catch (e) { qErr.value = e instanceof QueryError ? e.message : String(e); }
}, { immediate: true });

const kept = computed(() =>
  qErr.value ? rows.value : rows.value.filter((r) => evaluate(ast.value, r, qctx)));
const said = computed(() => (qErr.value ? "" : explain(ast.value)));
const pushed = computed(() => Object.keys(pushdown(ast.value)));

const t1 = () => Date.now() * 1000;
const PAGE = 1000, BUDGET = 6;

async function load() {
  loading.value = true; err.value = "";
  const until = t1(), since = until - WINDOWS[winIdx.value].us;
  const base = { ...pushdown(ast.value), since, until, limit: PAGE };
  const got: Row[] = [];
  try {
    for (let p = 0; p < BUDGET; p++) {
      const r = await api.get("/querylog" + api.qs({ ...base, offset: p * PAGE }));
      total.value = r.total ?? 0;
      got.push(...(r.rows || []));
      if (!r.rows || r.rows.length < PAGE) break;
    }
    rows.value = got.sort((a, b) => b.ts - a.ts);
  } catch (e: any) {
    err.value = e?.message || "the query log could not be read";
  } finally { loading.value = false; }
}

/* Follow mode joins live rows to the head. Off by default: a table that moves
 * while you read it is the problem the Live view exists to solve. */
watch(() => store.state.liveTotal, () => {
  if (!follow.value) return;
  const live = store.state.live;
  if (!live.length) return;
  const newest = rows.value.length ? rows.value[0].ts : 0;
  const add = live.map((e) => ({
    ts: e.ts > 1e12 ? e.ts : Math.round(e.ts * 1e6),
    client_ip: e.client, qname: e.domain, qtype: e.type, action: e.action,
    rcode: e.rcode, upstream: e.upstream, elapsed_us: e.elapsed_us, reason: e.reason,
    answers: "[]",
  } as Row)).filter((r) => r.ts > newest);
  if (add.length) rows.value = [...add.sort((a, b) => b.ts - a.ts), ...rows.value].slice(0, 8000);
});

watch(queryText, () => router.replace({ query: { ...route.query, q: queryText.value || undefined } }));
onMounted(load);

const ago = (us: number) => {
  const d = (Date.now() * 1000 - us) / 1e6;
  if (d < 1) return "now";
  if (d < 60) return `${Math.floor(d)}s`;
  if (d < 3600) return `${Math.floor(d / 60)}m`;
  if (d < 86400) return `${Math.floor(d / 3600)}h`;
  return `${Math.floor(d / 86400)}d`;
};
const stamp = (us: number) => new Date(us / 1000).toISOString().replace("T", " ").slice(0, 23) + "Z";
const ms = (us?: number) => (!us ? "—" : us >= 1000 ? `${(us / 1000).toFixed(1)} ms` : `${us} µs`);

function exportCsv() {
  download("querylog.csv", toCsv(kept.value.map((r) => ({
    ts: stamp(r.ts), client: r.client_ip, name: r.qname, type: r.qtype,
    outcome: kindOf(r), rcode: r.rcode, ms: (r.elapsed_us || 0) / 1000,
    rule: r.rule || "", source: r.source || "", upstream: r.upstream || "",
  }))), "text/csv");
}
function exportNdjson() {
  download("querylog.ndjson", kept.value.map((r) => JSON.stringify(r)).join("\n"),
           "application/x-ndjson");
}
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Log</h2>
      <div class="acts">
        <label class="sw" :class="{ on: follow }">
          <input type="checkbox" v-model="follow" style="position:absolute;opacity:0" />
          <span class="sw-box" /><b>follow</b>
        </label>
        <select class="sel" style="width:auto" v-model.number="winIdx" @change="load">
          <option v-for="(w, i) in WINDOWS" :key="w.label" :value="i">{{ w.label }}</option>
        </select>
        <button class="btn" @click="exportCsv"><Ico name="copy" /> CSV</button>
        <button class="btn" @click="exportNdjson">NDJSON</button>
      </div>
    </header>

    <div class="vw-body">
      <div class="sec">
        <input class="inp" v-model="queryText" spellcheck="false" @keydown.enter="load"
               placeholder="failed or ms>500 · client=10.0.4.71 and blocked" />
        <p class="sec-note" style="margin-top:8px" v-if="qErr" :style="{ color: 'var(--o-failed)' }">
          {{ qErr }}
        </p>
        <p class="sec-note" style="margin-top:8px" v-else-if="queryText">
          {{ said }}
          <b v-if="pushed.length">
            The server answered {{ pushed.join(", ") }}; the rest was applied here.
          </b>
        </p>
        <p class="sec-note" v-else>
          {{ nf.format(rows.length) }} rows loaded of {{ nf.format(total) }} in this
          window.
        </p>
      </div>

      <div class="sec" style="padding-top:0">
        <table class="tb">
          <thead>
            <tr>
              <th style="width:62px">When</th>
              <th style="width:132px">Device</th>
              <th>Name</th>
              <th style="width:56px">Type</th>
              <th style="width:104px">Outcome</th>
              <th class="r" style="width:76px">Took</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="(r, i) in kept.slice(0, 500)" :key="r.ts + '-' + i">
              <tr class="click" :class="{ on: open === i }" @click="open = open === i ? null : i">
                <td :title="stamp(r.ts)" style="color:var(--b-ink-4)">{{ ago(r.ts) }}</td>
                <td class="id">{{ r.client_id || r.client_ip }}</td>
                <td class="id">
                  <span class="dim">{{ align(r.qname).sub }}{{ align(r.qname).sub ? "." : "" }}</span>{{ align(r.qname).reg }}
                </td>
                <td>{{ r.qtype }}</td>
                <td>
                  <span class="oc" :class="kindOf(r)">
                    <i :style="kindOf(r) === 'unknown' ? '' : `background:var(--o-${kindOf(r)})`" />
                    {{ meta(kindOf(r)).label }}
                  </span>
                </td>
                <td class="r">{{ ms(r.elapsed_us) }}</td>
              </tr>
              <!-- the chain, in place: a drawer would cover the rows you are
                   comparing this one against -->
              <tr class="det" v-if="open === i">
                <td colspan="6">
                  <dl class="kvs" style="padding:10px 0">
                    <dt>Asked</dt>
                    <dd>{{ r.qname }} {{ r.qtype }} · {{ stamp(r.ts) }}</dd>
                    <dt>Verdict</dt>
                    <dd class="ui">
                      {{ outcomeOf(r).sentence }}
                      <span class="tag mine" v-if="isAuthored(r)">a rule you wrote</span>
                      <span class="tag warn" v-if="isStale(r)">stale</span>
                    </dd>
                    <template v-if="r.rule">
                      <dt>Rule</dt><dd>{{ r.rule }}<span class="note" v-if="r.source"> · {{ r.source }}</span></dd>
                    </template>
                    <dt>Path</dt>
                    <dd class="ui" v-if="outcomeOf(r).travelled">
                      {{ r.upstream || "upstream not recorded" }} · {{ ms(r.elapsed_us) }}
                    </dd>
                    <dd class="ui" v-else style="color:var(--b-ink-3)">nothing left this machine</dd>
                    <dt>Result</dt>
                    <dd>{{ r.rcode }}<template v-if="answerList(r.answers).length"> · {{ answerList(r.answers).join(" ") }}</template></dd>
                    <template v-if="r.reason">
                      <dt>Note</dt><dd class="ui">{{ r.reason }}</dd>
                    </template>
                  </dl>
                  <div class="row-acts" style="padding-bottom:10px">
                    <button class="btn" @click.stop="router.push({ path: '/', query: { q: `name=${r.qname}` } })">
                      open in Browse
                    </button>
                    <button class="btn" @click.stop="store.inspect('client', r.client_ip)">
                      this device
                    </button>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
        <p class="tb-foot" v-if="kept.length > 500">
          Showing the newest 500 of {{ nf.format(kept.length) }} matching rows.
          Narrow the query or the window to account for the rest.
        </p>
        <p class="b-void-state" v-if="!loading && !kept.length">
          No rows in the last {{ WINDOWS[winIdx].label.toLowerCase() }}<template v-if="queryText"> matching this query</template>.
        </p>
        <p class="b-void-state" v-if="loading">Reading the query log…</p>
        <p class="b-warn" v-if="err">{{ err }}</p>
      </div>
    </div>
  </div>
</template>
