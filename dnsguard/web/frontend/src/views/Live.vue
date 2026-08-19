<script setup lang="ts">
/* Live — what is happening right now.
 *
 * Every live DNS view ever built is a casino ticker: rows fly upward, numbers
 * spin, and the operator learns to ignore it. The problem is that motion is
 * being used to signal *recency*, which the eye already gets from position. So:
 *
 *   · rows accrue at the top and do not animate. New is at the top; that is the
 *     whole signal
 *   · the tape freezes while the pointer is over it. Reading a line that is
 *     about to be pushed down is the single most common frustration in a live
 *     log, and it is trivially avoidable
 *   · the numbers are rates, not totals. "1.9 per second" is actionable;
 *     "1,284,203 queries since boot" is a milestone, not information
 *   · one ribbon shows the last 240 outcomes as a row of ticks. A burst of
 *     refusals or a cluster of failures is visible in it without reading a
 *     single word, and it costs 22 pixels of height
 *
 * The rate is measured from the arrival timestamps we actually hold rather than
 * from a counter difference, so it stays honest when the socket reconnects.
 */
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRouter } from "vue-router";
import { align } from "../lib/dnsname";
import { KINDS, kindOf, meta } from "../lib/outcome";
import type { Row } from "../lib/qlang";
import { store, type QueryEvent } from "../lib/store";
import Ico from "../ui/Ico.vue";

const router = useRouter();
const s = store.state;
const frozen = ref(false);
const nf = new Intl.NumberFormat();

/** WS events carry seconds; everything else in this app is microseconds. */
const asRow = (e: QueryEvent): Row => ({
  ts: e.ts > 1e12 ? e.ts : Math.round(e.ts * 1e6),
  client_ip: e.client, qname: e.domain, qtype: e.type, action: e.action,
  rcode: e.rcode, upstream: e.upstream, elapsed_us: e.elapsed_us,
  reason: e.reason, answers: "[]",
});

const feed = computed(() => s.live.map(asRow));
const tape = computed(() => feed.value.slice(0, 120));
const ribbon = computed(() => feed.value.slice(0, 240).reverse());

/* Rate from the timestamps in hand: count what arrived inside a trailing window
 * and divide. A counter delta lies across a reconnect. */
const now = ref(Date.now() * 1000);
let tick: number | undefined;
onMounted(() => { tick = window.setInterval(() => { now.value = Date.now() * 1000; }, 1000); });
onUnmounted(() => { if (tick) clearInterval(tick); });

function rate(seconds: number): number {
  const cut = now.value - seconds * 1e6;
  const n = feed.value.filter((r) => r.ts >= cut).length;
  return Math.round((n / seconds) * 10) / 10;
}
const r10 = computed(() => rate(10));
const r60 = computed(() => rate(60));
/* Whether the last ten seconds are unusual for this network, stated as a
 * comparison rather than as a threshold nobody configured. */
const drift = computed(() => {
  if (!r60.value) return "";
  const f = r10.value / r60.value;
  if (f > 2) return `${f.toFixed(1)}× the last minute`;
  if (f < 0.4 && r60.value > 1) return `quieter than the last minute`;
  return "";
});

const split = computed(() => {
  const by: Record<string, number> = {};
  for (const r of feed.value) by[kindOf(r)] = (by[kindOf(r)] || 0) + 1;
  return KINDS.filter((k) => by[k]).map((k) => ({
    kind: k, label: meta(k).label, n: by[k],
    pct: Math.round((by[k] / Math.max(1, feed.value.length)) * 100),
  }));
});

const hhmmss = (us: number) => {
  const d = new Date(us / 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
};
const ms = (us?: number) => (!us ? "" : us >= 1000 ? `${(us / 1000).toFixed(0)}ms` : `${us}µs`);

/** Any row is a way into the browser, scoped to that name. */
function open(r: Row) {
  router.push({ path: "/", query: { q: `name=${r.qname.replace(/\.$/, "").toLowerCase()}` } });
}
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Live</h2>
      <div class="acts">
        <button class="btn" @click="store.togglePause()">
          <Ico :name="s.paused ? 'next' : 'held'" />
          {{ s.paused ? "resume" : "hold" }}
        </button>
        <button class="btn" @click="store.clearLive()">clear</button>
      </div>
    </header>

    <div class="vw-body">
      <!-- rate: two numbers and a comparison, no tiles -->
      <div class="sec">
        <div style="display:flex;gap:44px;flex-wrap:wrap;align-items:flex-end">
          <div>
            <div class="ev-big"><b>{{ r10 }}</b><span>per second, last 10s</span></div>
            <p class="sec-note" style="margin:4px 0 0" v-if="drift">{{ drift }}</p>
          </div>
          <div class="ev-big" style="color:var(--b-ink-3)">
            <b style="font-size:var(--b-ui-s);color:var(--b-ink-2)">{{ r60 }}</b>
            <span>per second, last minute</span>
          </div>
          <div class="ev-big" style="color:var(--b-ink-3)">
            <b style="font-size:var(--b-ui-s);color:var(--b-ink-2)">{{ nf.format(s.liveTotal) }}</b>
            <span>seen since this page opened</span>
          </div>
          <div class="ev-big" style="color:var(--b-ink-3)" v-if="s.stats">
            <b style="font-size:var(--b-ui-s);color:var(--b-ink-2)">{{ s.stats.latency_p95_ms }}</b>
            <span>ms at p95</span>
          </div>
        </div>
      </div>

      <!-- the ribbon: 240 outcomes in one row -->
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Last 240 outcomes</h5>
        </div>
        <div class="ribbon" v-if="ribbon.length">
          <i v-for="(r, i) in ribbon" :key="i"
             :style="kindOf(r) === 'unknown'
               ? 'border:1px dashed var(--b-ink-4)'
               : `background:var(--o-${kindOf(r)})`"
             :title="`${r.qname} — ${meta(kindOf(r)).label}`" />
        </div>
        <p class="b-void-state" v-else>
          Nothing yet.
        </p>
        <div class="mtr-l" v-if="split.length">
          <span class="oc" v-for="k in split" :key="k.kind" :class="k.kind">
            <i :style="k.kind === 'unknown' ? '' : `background:var(--o-${k.kind})`" />
            <span class="b-cap">{{ k.label }} {{ k.pct }}%</span>
          </span>
        </div>
      </div>

      <!-- the tape -->
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Tape</h5>
          <span class="b-cap" v-if="frozen || s.paused">
            {{ s.paused ? "held" : "frozen while you read" }}
          </span>
        </div>
        <div class="tape" @mouseenter="frozen = true" @mouseleave="frozen = false">
          <div class="tape-r" v-for="(r, i) in tape" :key="r.ts + '-' + i"
               :class="'k-' + kindOf(r)" @click="open(r)">
            <span class="tape-t">{{ hhmmss(r.ts) }}</span>
            <span class="tape-o">{{ meta(kindOf(r)).label }}</span>
            <span class="tape-n">
              <span class="dim">{{ align(r.qname).sub }}{{ align(r.qname).sub ? "." : "" }}</span>{{ align(r.qname).reg }}
            </span>
            <span class="tape-d">{{ r.client_ip }}</span>
            <span class="tape-ms">{{ ms(r.elapsed_us) }}</span>
          </div>
          <p class="b-void-state" v-if="!tape.length">
            Waiting for the first query.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>
