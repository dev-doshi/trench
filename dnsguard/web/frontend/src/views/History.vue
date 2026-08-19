<script setup lang="ts">
/* History — aggregate over the long term.
 *
 * The backend has a real pivot engine behind /analytics: pick a metric, a
 * grouping and a time bucket. The conventional UI for that is four dropdowns in
 * a toolbar, which tells the operator nothing about what they are about to ask.
 *
 * So the controls are a *sentence*. "Count of queries by device per hour over
 * the last 7 days" reads as a question and each underlined part is the control
 * that changes it. The sentence is not decoration: it is the only place the
 * current query is stated, and it makes an incoherent combination obvious before
 * you run it.
 *
 * The chart is chosen by the shape of the answer, not by a picker:
 *   · bucketed over time      → direct-labelled lines (ui/Trend)
 *   · day-of-week × hour      → the rhythm grid (ui/Rhythm), because periodicity
 *                               is two-dimensional and a line unrolls it into
 *                               nonsense
 *   · grouped, not bucketed   → a ranked table with spines
 * Offering a chart type picker would let the operator draw a rhythm as a line,
 * and there is no reading of that chart that is correct.
 */
import { computed, onMounted, ref } from "vue";
import { api } from "../lib/api";
import Rhythm from "../ui/Rhythm.vue";
import Spine from "../ui/Spine.vue";
import Trend from "../ui/Trend.vue";

const METRICS = [
  { key: "count", label: "count of queries", unit: "" },
  { key: "avg_latency", label: "average time to answer", unit: "ms" },
  { key: "max_latency", label: "worst time to answer", unit: "ms" },
];
const GROUPS = [
  { key: "none", label: "everything together" },
  { key: "action", label: "outcome" },
  { key: "client_ip", label: "device" },
  { key: "qtype", label: "record type" },
  { key: "rcode", label: "response code" },
  { key: "upstream", label: "upstream resolver" },
  { key: "qname", label: "name" },
];
const BUCKETS = [
  { key: "hour", label: "per hour" },
  { key: "minute", label: "per minute" },
  { key: "day", label: "per day" },
  { key: "dow_hour", label: "by weekday and hour" },
  { key: "none", label: "as a single total" },
];
const SPANS = [
  { key: 1, label: "the last day" },
  { key: 7, label: "the last 7 days" },
  { key: 30, label: "the last 30 days" },
];

const metric = ref("count");
const group = ref("action");
const bucket = ref("hour");
const days = ref(7);
const nameFilter = ref("");

const data = ref<any>(null);
const loading = ref(false);
const err = ref("");
const nf = new Intl.NumberFormat();

const unit = computed(() => METRICS.find((m) => m.key === metric.value)!.unit);

async function run() {
  loading.value = true; err.value = "";
  const until = Date.now() * 1000;
  const since = until - days.value * 86400e6;
  try {
    data.value = await api.get("/analytics" + api.qs({
      since, until, bucket: bucket.value, group: group.value, metric: metric.value,
      qname: nameFilter.value || undefined, top: 8,
    }));
  } catch (e: any) {
    err.value = e?.message || "the aggregation could not be run";
    data.value = null;
  } finally { loading.value = false; }
}
onMounted(run);

/* /analytics returns one of three shapes; which one tells us what to draw. */
const series = computed(() => {
  const s = data.value?.series;
  if (!Array.isArray(s)) return [];
  return s.map((x: any) => ({
    name: String(x.group ?? "all"),
    points: (x.points || []) as [number, number][],
    kind: ["blocked", "blocked", "failed", "cached"].includes(String(x.group))
      ? String(x.group) === "blocked" ? "blocked" : String(x.group)
      : undefined,
  }));
});
const cells = computed(() => (data.value?.cells || []) as [number, number, number][]);
const ranked = computed(() => {
  const rows = (data.value?.rows || []) as [string, number][];
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return rows.map(([name, v]) => ({ name, v, max }));
});

const shape = computed(() => {
  if (cells.value.length) return "rhythm";
  if (series.value.length) return "trend";
  if (ranked.value.length) return "ranked";
  return "none";
});
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>History</h2>
    </header>

    <div class="vw-body">
      <!-- the question as a sentence; each control is the word it changes -->
      <div class="sec">
        <p style="font:400 var(--b-loud)/1.6 var(--b-read);color:var(--b-ink-2);margin:0;max-width:none">
          Show the
          <select class="sel sen" v-model="metric" @change="run">
            <option v-for="m in METRICS" :key="m.key" :value="m.key">{{ m.label }}</option>
          </select>
          by
          <select class="sel sen" v-model="group" @change="run">
            <option v-for="g in GROUPS" :key="g.key" :value="g.key">{{ g.label }}</option>
          </select>
          <select class="sel sen" v-model="bucket" @change="run">
            <option v-for="b in BUCKETS" :key="b.key" :value="b.key">{{ b.label }}</option>
          </select>
          over
          <select class="sel sen" v-model.number="days" @change="run">
            <option v-for="s in SPANS" :key="s.key" :value="s.key">{{ s.label }}</option>
          </select>.
        </p>
        <div style="display:flex;gap:10px;align-items:center;margin-top:12px">
          <input class="inp" style="max-width:340px" v-model="nameFilter"
                 placeholder="limit to names containing…" @keydown.enter="run" />
          <button class="btn hard" @click="run" :disabled="loading">
            {{ loading ? "running…" : "run" }}
          </button>
        </div>
        <p class="b-warn" v-if="err" style="margin-top:10px">{{ err }}</p>
      </div>

      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">
            {{ shape === "rhythm" ? "Weekday rhythm"
             : shape === "trend" ? "Over time" : shape === "ranked" ? "Ranked" : "Result" }}
          </h5>
          <span class="b-cap" v-if="unit">{{ unit }}</span>
        </div>

        <Rhythm v-if="shape === 'rhythm'" :cells="cells" :unit="unit || 'queries'" />
        <Trend v-else-if="shape === 'trend'" :series="series" :height="260" />

        <table class="tb" v-else-if="shape === 'ranked'">
          <thead>
            <tr>
              <th>{{ GROUPS.find(g => g.key === group)?.label || "group" }}</th>
              <th class="r" style="width:120px">{{ unit || "queries" }}</th>
              <th style="width:34%">share</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in ranked" :key="r.name">
              <td class="id">{{ r.name }}</td>
              <td class="r">{{ nf.format(r.v) }}</td>
              <td>
                <Spine :by="{ cache: 0, upstream: r.v, local: 0, blocked: 0, failed: 0, unknown: 0 }"
                       :total="r.v" :max="r.max" />
              </td>
            </tr>
          </tbody>
        </table>

        <p class="b-void-state" v-else-if="loading">Running the aggregation…</p>
        <p class="b-void-state" v-else>
          Nothing recorded for that question in this span.
        </p>
      </div>
    </div>
  </div>
</template>

<style>
/* a control that sits inside a sentence looks like the word it replaces:
   underlined, inheriting the serif, no chrome until you touch it */
.sel.sen {
  width: auto; display: inline; background: none; border: none;
  border-bottom: 1px solid var(--b-edge); border-radius: 0;
  font: 400 var(--b-loud)/1.6 var(--b-read); color: var(--b-ink);
  padding: 0 2px; margin: 0 2px; cursor: pointer;
}
.sel.sen:hover { border-bottom-color: var(--b-ink); }
</style>
