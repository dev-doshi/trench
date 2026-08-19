<script setup lang="ts">
/* Evidence: what is true about the current selection, and — when the selection
 * is one query — how that one decision was reached.
 *
 * Two modes in one panel rather than two panels, because they are the same
 * question at two magnifications and switching between them should not move
 * anything on screen. A selection shows composition, cost and the shape of its
 * activity. A single row shows the causal chain: who asked, what was asked, what
 * decided it, whether it travelled, what came back.
 *
 * The chain is a fixed grid with a fixed row order, including rows that do not
 * apply — those render as a stated absence. A missing PATH is the meaning for a
 * cache hit or a refusal, and hiding the row would throw that away.
 */
import { computed } from "vue";
import { align, answerList, classifyAddr, isSinkhole, shape } from "../lib/dnsname";
import { KINDS, isAuthored, isStale, meta, outcomeOf } from "../lib/outcome";
import type { Summary } from "../lib/facets";
import type { Row } from "../lib/qlang";
import { store } from "../lib/store";
import { copyText } from "../lib/util";
import Ico from "./Ico.vue";
import Percentiles from "./Percentiles.vue";

const props = defineProps<{
  /** what the columns have narrowed to */
  rows: Row[];
  summary: Summary;
  /** the one row under inspection, when there is one */
  row: Row | null;
  /** heading: the selected path */
  path: { label: string; value: string }[];
  windowFrom: number;
  /** which occurrence of a picked name is shown, and how many there are */
  occurrence?: number;
  occurrences?: number;
}>();
const emit = defineEmits<{ (e: "query", q: string): void; (e: "step", d: number): void }>();

const ms = (us: number | undefined) =>
  !us ? "—" : us >= 1000 ? `${(us / 1000).toFixed(1)} ms` : `${us} µs`;

const nf = new Intl.NumberFormat();

// ── selection mode ────────────────────────────────────────────────────────
const legend = computed(() =>
  KINDS.filter((k) => props.summary.by[k] > 0).map((k) => ({
    kind: k,
    label: meta(k).label,
    n: props.summary.by[k],
    pct: Math.round((props.summary.by[k] / Math.max(1, props.summary.total)) * 100),
  })));

const head = computed(() => props.path.length ? props.path[props.path.length - 1] : null);

// ── single-row mode ───────────────────────────────────────────────────────
const oc = computed(() => (props.row ? outcomeOf(props.row) : null));
const name = computed(() => (props.row ? props.row.qname.replace(/\.$/, "").toLowerCase() : ""));
const parts = computed(() => align(name.value));
const sh = computed(() => (props.row ? shape(name.value) : null));
const answers = computed(() => answerList(props.row?.answers));

const when = computed(() => {
  if (!props.row) return "";
  const d = new Date(props.row.ts / 1000);
  return d.toISOString().replace("T", " ").replace("Z", "") + " UTC";
});

/** Every sighting of this name in what is loaded — the basis for the local facts. */
const sameName = computed(() =>
  props.row ? props.rows.filter((r) => r.qname.toLowerCase() === props.row!.qname.toLowerCase()) : []);
const askers = computed(() => new Set(sameName.value.map((r) => r.client_ip)).size);
const first = computed(() => (sameName.value.length ? Math.min(...sameName.value.map((r) => r.ts)) : 0));
/** If the earliest sighting is at the edge of the window, "first seen" is an
 *  artefact of how much we loaded, and saying it would be a lie. */
const firstIsEdge = computed(() => !first.value || first.value - props.windowFrom < 2_000_000);
const retried = computed(() => {
  if (!props.row) return 0;
  const t = props.row.ts;
  return sameName.value.filter((r) => r.client_ip === props.row!.client_ip
    && r.ts > t && r.ts - t < 40_000_000).length;
});

const decided = computed(() => {
  const r = props.row;
  if (!r || !oc.value) return "";
  if (oc.value.kind === "blocked") return r.rule || r.reason || "blocked by policy";
  if (oc.value.kind === "failed") return r.reason || "no answer obtained";
  if (oc.value.kind === "cache") return isStale(r) ? "cache entry past its TTL, served while a refresh was attempted" : "a live cache entry";
  if (oc.value.kind === "local") return "this resolver is authoritative for the name";
  return "no policy matched — resolved normally";
});

function copyChain() {
  const r = props.row;
  if (!r || !oc.value) return;
  const L = (k: string, v: string) => k.padEnd(9) + v;
  copyText([
    L("WHO", `${r.client_ip}${r.client_id ? "  " + r.client_id : ""}`),
    L("ASKED", `${name.value}  ${r.qtype}  ${when.value}`),
    L("VERDICT", `${oc.value.sentence} — ${decided.value}`),
    L("SOURCE", r.source || "—"),
    L("PATH", oc.value.travelled ? `${r.upstream || "upstream"}  ${ms(r.elapsed_us)}` : "nothing left this machine"),
    L("RESULT", `${r.rcode}${answers.value.length ? "  " + answers.value.join(" ") : ""}`
      + (retried.value ? `  retried ${retried.value}x` : "")),
  ].join("\n"));
  store.toast("Copied", "the chain as plain text");
}
</script>

<template>
  <aside class="ev">
    <!-- ══════════════════════════════════════════════ one query ══════════ -->
    <template v-if="row && oc">
      <div class="ev-h">
        <div style="display:flex;align-items:baseline;gap:10px">
          <h5 class="b-cap">Chain</h5>
          <template v-if="(occurrences ?? 0) > 1">
            <span class="b-cap" style="color:var(--b-ink-2)">{{ (occurrence ?? 0) + 1 }}&thinsp;/&thinsp;{{ occurrences }}</span>
            <button class="btn-q" @click="emit('step', -1)" title="previous occurrence (p)">
              <Ico name="up" :size="12" />
            </button>
            <button class="btn-q" @click="emit('step', 1)" title="next occurrence (n)">
              <Ico name="down" :size="12" />
            </button>
          </template>
          <span class="b-cap" style="margin-left:auto">{{ when }}</span>
        </div>
        <span class="val"><span class="dim">{{ parts.sub }}{{ parts.sub ? "." : "" }}</span>{{ parts.reg }}</span>
      </div>

      <dl class="dep">
        <dt>Who</dt>
        <dd>
          <a class="lnk" @click="store.inspect('client', row.client_ip)">{{ row.client_ip }}</a>
          <span v-if="row.client_id" class="note">{{ row.client_id }}</span>
          <span v-else class="none">unnamed — known only by address</span>
        </dd>

        <dt>Asked</dt>
        <dd>
          {{ row.qtype }} · over {{ row.proto || "an unrecorded transport" }}
          <span class="tag warn" v-if="sh?.punycode">punycode</span>
          <span class="tag warn" v-if="sh?.mixedScript">mixed script</span>
          <span class="tag" v-if="sh?.hexish || sh?.digitHeavy">machine-shaped label</span>
        </dd>

        <div style="display:none" />
        <dt :class="{ authored: isAuthored(row) }">Verdict</dt>
        <dd :class="{ authored: isAuthored(row) }">
          <span class="said">{{ oc.sentence }}</span>
          <span>{{ decided }}</span>
          <span class="tag mine" v-if="isAuthored(row)">a rule you wrote</span>
          <span class="tag warn" v-if="isStale(row)">stale</span>
        </dd>

        <dt>Source</dt>
        <dd v-if="row.source">
          {{ row.source === "custom" ? "your own list" : row.source }}
          <button class="btn-q" @click="emit('query', `source=${row.source}`)">
            everything from this list
          </button>
        </dd>
        <dd v-else class="void">no rule was involved</dd>

        <dt>Path</dt>
        <dd v-if="oc.travelled">
          {{ row.upstream || "upstream not recorded" }}
          <span class="note">{{ ms(row.elapsed_us) }}</span>
        </dd>
        <dd v-else class="void">
          <span class="cut">nothing left this machine</span>
          <span class="note" v-if="oc.kind === 'blocked'">the name was never asked of anyone</span>
        </dd>

        <dt>Result</dt>
        <dd>
          <span class="said">{{ row.rcode || "—" }}</span>
          <template v-if="answers.length">
            <span v-for="a in answers.slice(0, 8)" :key="a" class="addr">
              {{ a }}
              <span class="note" v-if="isSinkhole(a)">sinkhole</span>
              <span class="note" v-else-if="classifyAddr(a) === 'private'">private</span>
            </span>
          </template>
          <span class="none" v-else>no records</span>
          <span class="tag warn" v-if="retried">client retried {{ retried }}× within 40s</span>
        </dd>

        <dt>Locally</dt>
        <dd class="void" v-if="firstIsEdge">
          First sighting unknown — this name was already in use when the loaded
          window begins.
        </dd>
        <dd v-else>
          <span class="said">{{ sameName.length }}</span>
          <span class="note">
            sighting{{ sameName.length === 1 ? "" : "s" }} in view, from
            {{ askers }} device{{ askers === 1 ? "" : "s" }}, first at
            {{ new Date(first / 1000).toISOString().slice(11, 19) }}
          </span>
        </dd>
      </dl>

      <div class="ev-sec">
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn-q" @click="copyChain">
            <Ico name="copy" :size="13" style="display:inline-block;vertical-align:-2px" />
            copy chain
          </button>
          <button class="btn-q" @click="emit('query', `name=${name}`)">every query for this name</button>
        </div>
      </div>

    </template>

    <!-- ══════════════════════════════════════════════ a selection ════════ -->
    <template v-else>
      <div class="ev-h">
        <h5 class="b-cap">{{ head ? head.label : "All traffic" }}</h5>
        <span class="val" v-if="head">{{ head.value }}</span>
        <span class="val hint" v-else>Select a row.</span>
      </div>

      <div class="ev-sec">
        <div class="ev-big">
          <b>{{ nf.format(summary.total) }}</b><span>queries</span>
          <span style="margin-left:auto" class="b-cap">
            {{ summary.names }} names · {{ summary.devices }} devices
          </span>
        </div>
        <div class="ev-legend">
          <div v-for="l in legend" :key="l.kind">
            <i :style="l.kind === 'unknown'
                 ? 'border:1px dashed var(--b-ink-4)'
                 : `background:var(--o-${l.kind})`" />
            <b>{{ l.label }}</b><u>{{ nf.format(l.n) }}</u><s>{{ l.pct }}%</s>
          </div>
        </div>
        <p class="ev-note" v-if="summary.authored">
          {{ summary.authored }} decided by a rule you wrote.
        </p>
        <p class="ev-note" style="color:var(--o-failed)" v-if="summary.stale">
          {{ summary.stale }} served past their TTL.
        </p>
      </div>

      <div class="ev-sec">
        <h5 class="b-cap">Time to answer</h5>
        <Percentiles :p50="summary.p50" :p95="summary.p95" :p99="summary.p99" />
      </div>

      <div class="ev-sec" v-if="path.length">
        <h5 class="b-cap">Selection</h5>
        <dl class="keys-tbl" style="grid-template-columns:82px 1fr">
          <template v-for="p in path" :key="p.label">
            <dt style="font-family:var(--b-ui);font-weight:500;color:var(--b-ink-3)">{{ p.label }}</dt>
            <dd class="b-id">{{ p.value }}</dd>
          </template>
        </dl>
      </div>
    </template>
  </aside>
</template>
