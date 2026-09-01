<script setup lang="ts">
/* The span band: when the current selection happened.
 *
 * Time is not the organising axis of this console — the namespace is — so time
 * appears as a property of whatever you have selected, in one band, rather than
 * as a wall of lanes. A time series of one thing is legible; forty at once is
 * texture.
 *
 * Answers rise from a shared baseline, refusals hang below it. That is worth
 * more than a stacked bar: a device retrying against a block shows refusals
 * climbing while answers stay flat, and a device that has gone quiet shows both
 * collapse together. A stack renders those two identically.
 *
 * Answers are split at the baseline into what cost a round trip and what did
 * not, so the band reads the cache as well as the traffic — a healthy resolver
 * is mostly the quiet fill, and a cache that stops working shows the mid fill
 * swallowing the band while the total never moves.
 *
 * Failures are marks on the baseline rather than a third stacked series, because
 * a failure is not a quantity you compare against cache hits. Their height is
 * scaled against the worst bucket, not fixed: a fixed tick turns a steady
 * trickle of one-per-minute into a solid rule across the chart, which reads as a
 * drawn axis and hides the actual spikes.
 */
import { computed, ref } from "vue";
import type { Bucket } from "../lib/facets";

const props = defineProps<{
  buckets: Bucket[];
  t0: number;
  t1: number;
  height?: number;
}>();

const H = computed(() => props.height ?? 54);
const W = 1000;
/* More room above than below: on any healthy network answers outnumber
 * refusals, so an even split would waste half the band. */
const mid = computed(() => Math.round(H.value * 0.66));

const peak = computed(() => {
  let up = 1, dn = 1, fail = 1;
  for (const b of props.buckets) {
    up = Math.max(up, b.free + b.travelled);
    dn = Math.max(dn, b.blocked);
    fail = Math.max(fail, b.failed);
  }
  return { up, dn, fail };
});

const bw = computed(() => W / Math.max(1, props.buckets.length));

const bars = computed(() => {
  const upRoom = mid.value - 3, dnRoom = H.value - mid.value - 3;
  return props.buckets.map((b, i) => {
    const free = (b.free / peak.value.up) * upRoom;
    const travelled = (b.travelled / peak.value.up) * upRoom;
    return {
      x: i * bw.value,
      free, travelled,
      dn: (b.blocked / peak.value.dn) * dnRoom,
      fail: b.failed ? Math.max(1.5, (b.failed / peak.value.fail) * 7) : 0,
    };
  });
});

const ticks = computed(() => {
  const span = props.t1 - props.t0;
  const STEPS = [60e6, 300e6, 900e6, 3600e6, 10800e6, 21600e6, 86400e6];
  const step = STEPS.find((s) => span / s <= 8) ?? STEPS.at(-1)!;
  const out: { x: number; label: string }[] = [];
  for (let t = Math.ceil(props.t0 / step) * step; t <= props.t1; t += step) {
    const d = new Date(t / 1000);
    out.push({
      x: ((t - props.t0) / span) * W,
      label: step >= 86400e6
        ? d.toLocaleDateString([], { month: "short", day: "numeric" })
        : `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`,
    });
  }
  return out;
});

const bwPx = computed(() => Math.max(0.7, bw.value - 0.35));

/* ── reading a bucket ──────────────────────────────────────────────────────
 * The band showed shape and nothing else: you could see that something spiked
 * and had no way to ask when, or how much. Hovering names the bucket under the
 * pointer and gives its four counts. */
const hover = ref<number | null>(null);

function track(e: MouseEvent) {
  const el = e.currentTarget as SVGSVGElement;
  const r = el.getBoundingClientRect();
  const i = Math.floor(((e.clientX - r.left) / r.width) * props.buckets.length);
  hover.value = i >= 0 && i < props.buckets.length ? i : null;
}

const reading = computed(() => {
  if (hover.value === null) return null;
  const b = props.buckets[hover.value];
  if (!b) return null;
  const span = props.t1 - props.t0;
  const t = props.t0 + (span * (hover.value + 0.5)) / props.buckets.length;
  const d = new Date(t / 1000);
  return {
    x: (hover.value + 0.5) * bw.value,
    when: `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`,
    cached: b.free, forwarded: b.travelled, blocked: b.blocked, failed: b.failed,
    total: b.free + b.travelled + b.blocked + b.failed,
  };
});
</script>

<template>
  <div class="spanwrap">
  <svg :viewBox="`0 0 ${W} ${H + 14}`" preserveAspectRatio="none" role="img"
       aria-label="activity over the selected window, answers above the line and blocked below"
       @mousemove="track" @mouseleave="hover = null">
    <g>
      <line v-for="t in ticks" :key="'g' + t.x" :x1="t.x" y1="0" :x2="t.x" :y2="H"
            stroke="var(--b-edge-soft)" stroke-width="1" vector-effect="non-scaling-stroke" />
    </g>

    <!-- answered at no network cost: cache and local authority -->
    <g fill="var(--o-cache)">
      <rect v-for="b in bars" :key="'c' + b.x" :x="b.x" :y="mid - b.free"
            :width="bwPx" :height="b.free" />
    </g>
    <!-- answered, but it cost a round trip -->
    <g fill="var(--o-upstream)">
      <rect v-for="b in bars" :key="'u' + b.x" :x="b.x" :y="mid - b.free - b.travelled"
            :width="bwPx" :height="b.travelled" />
    </g>
    <!-- blocked, below the line -->
    <g fill="var(--o-blocked)">
      <rect v-for="b in bars" :key="'d' + b.x" :x="b.x" :y="mid + 1"
            :width="bwPx" :height="b.dn" />
    </g>
    <!-- failures: events on the line, scaled so a spike is visible and a
         trickle does not become a drawn rule -->
    <g fill="var(--o-failed)">
      <rect v-for="b in bars.filter(x => x.fail)" :key="'f' + b.x"
            :x="b.x" :y="mid - b.fail / 2" :width="bwPx" :height="b.fail" />
    </g>

    <line x1="0" :y1="mid" :x2="W" :y2="mid" class="zero" vector-effect="non-scaling-stroke" />

    <line v-if="reading" :x1="reading.x" y1="0" :x2="reading.x" :y2="H"
          class="cur" vector-effect="non-scaling-stroke" />

    <g class="tick">
      <text v-for="t in ticks" :key="'t' + t.x" :x="t.x + 3" :y="H + 11">{{ t.label }}</text>
    </g>
  </svg>
  <div class="span-read">
    <template v-if="reading">
    <b>{{ reading.when }}</b>
    <span><i style="background:var(--o-cache)" />cached <u>{{ reading.cached }}</u></span>
    <span><i style="background:var(--o-upstream)" />forwarded <u>{{ reading.forwarded }}</u></span>
    <span><i style="background:var(--o-blocked)" />blocked <u>{{ reading.blocked }}</u></span>
    <span v-if="reading.failed"><i style="background:var(--o-failed)" />failed <u>{{ reading.failed }}</u></span>
    </template>
  </div>
  </div>
</template>
