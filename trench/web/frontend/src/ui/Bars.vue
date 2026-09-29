<script setup lang="ts">
/* Stacked columns over time: one column per bucket, one segment per part.
 *
 * Stacked rather than lines because the parts of a query count do sum to the
 * whole — the reader wants "how busy" and "how much of it was blocked" from
 * the same mark. Hovering a column reads every part at that instant.
 */
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

export interface Stack { name: string; colour: string; values: number[] }

const props = withDefaults(defineProps<{
  /** bucket start, epoch seconds, ascending; `values` are parallel to it */
  times: number[];
  stacks: Stack[];
  height?: number;
}>(), { height: 240 });

/* The viewBox is kept at the drawn width, so one unit is one pixel: text and
 * strokes stay the same size whether the chart fills a page or a third of one. */
const W = ref(1000);
const box = ref<HTMLElement | null>(null);
let ro: ResizeObserver | null = null;
onMounted(() => {
  ro = new ResizeObserver(([e]) => { if (e.contentRect.width) W.value = Math.round(e.contentRect.width); });
  if (box.value) ro.observe(box.value);
});
onBeforeUnmount(() => ro?.disconnect());
const PAD = { t: 10, b: 24, l: 44, r: 6 };
const H = computed(() => props.height);

const totals = computed(() => props.times.map((_, i) =>
  props.stacks.reduce((a, s) => a + (s.values[i] || 0), 0)));

/* round the axis up to a 1/2/5 step so gridlines land on readable numbers */
const axis = computed(() => {
  const top = Math.max(1, ...totals.value);
  const mag = Math.pow(10, Math.floor(Math.log10(top)));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => top / s <= 4)!;
  const max = Math.ceil(top / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= max; v += step) ticks.push(v);
  return { max, ticks };
});

const slot = computed(() => (W.value - PAD.l - PAD.r) / Math.max(1, props.times.length));
const py = (v: number) => PAD.t + (1 - v / axis.value.max) * (H.value - PAD.t - PAD.b);
const fmt = (v: number) => v >= 10_000 ? `${Math.round(v / 1000)}k`
  : v >= 1000 ? `${(v / 1000).toFixed(1).replace(/\.0$/, "")}k` : String(v);

const cols = computed(() => props.times.map((t, i) => {
  const w = Math.max(1, slot.value * 0.72);
  const x = PAD.l + i * slot.value + (slot.value - w) / 2;
  let acc = 0;
  const segs = props.stacks.map((s) => {
    const v = s.values[i] || 0;
    const y1 = py(acc), y0 = py(acc + v);
    acc += v;
    return { colour: s.colour, y: y0, h: Math.max(0, y1 - y0) };
  }).filter((s) => s.h > 0);
  return { t, x, w, segs };
}));

const span = computed(() => (props.times.at(-1) ?? 0) - (props.times[0] ?? 0));
function stamp(t: number, long = false): string {
  const d = new Date(t * 1000);
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (long || span.value > 2 * 86400) {
    const day = d.toLocaleDateString([], { weekday: "short", day: "numeric" });
    return long ? `${day}, ${hm}` : day;
  }
  return hm;
}
/* About six labels on bucket boundaries. Over days, one per day at the first
 * bucket of that day, thinned to fit, so no day is silently skipped. */
const xTicks = computed(() => {
  const n = props.times.length;
  const at = (i: number) => ({ x: PAD.l + i * slot.value + slot.value / 2, label: stamp(props.times[i]) });
  if (span.value > 2 * 86400) {
    const days = props.times.map((_, i) => i).filter((i) => !i || stamp(props.times[i]) !== stamp(props.times[i - 1]));
    // a partial first day too narrow for its label gives way to the next
    if (days.length > 1 && (days[1] - days[0]) * slot.value < 60) days.shift();
    const keep = Math.ceil(days.length / Math.max(2, Math.floor(W.value / 70)));
    return days.filter((_, k) => k % keep === 0).map(at);
  }
  const every = Math.max(1, Math.ceil(n / Math.min(6, Math.floor(W.value / 70))));
  const out = [];
  for (let i = 0; i < n; i += every) out.push(at(i));
  return out;
});

const hover = ref<number | null>(null);
function track(e: MouseEvent) {
  const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
  const x = ((e.clientX - r.left) / r.width) * W.value;
  const i = Math.floor((x - PAD.l) / slot.value);
  hover.value = i >= 0 && i < props.times.length ? i : null;
}
const read = computed(() => {
  const i = hover.value;
  if (i === null) return null;
  return {
    label: stamp(props.times[i], true),
    total: totals.value[i],
    parts: props.stacks.map((s) => ({ name: s.name, colour: s.colour, v: s.values[i] || 0 })),
  };
});
</script>

<template>
  <div class="bars" ref="box">
    <div class="bars-read">
      <template v-if="read">
        <b>{{ read.label }}</b>
        <span>{{ read.total.toLocaleString() }} total</span>
        <span v-for="p in read.parts" :key="p.name"><i :style="{ background: p.colour }" />{{ p.name }}
          <u>{{ p.v.toLocaleString() }}</u></span>
      </template>
      <template v-else>
        <span v-for="s in stacks" :key="s.name"><i :style="{ background: s.colour }" />{{ s.name }}</span>
      </template>
    </div>
    <svg :viewBox="`0 0 ${W} ${H}`" role="img" aria-label="Stacked counts over time"
         @mousemove="track" @mouseleave="hover = null">
      <g>
        <template v-for="v in axis.ticks" :key="v">
          <line :x1="PAD.l" :x2="W - PAD.r" :y1="py(v)" :y2="py(v)" class="bars-grid" />
          <text :x="PAD.l - 8" :y="py(v) + 4" text-anchor="end" class="bars-lb">{{ fmt(v) }}</text>
        </template>
      </g>
      <rect v-if="hover !== null" :x="PAD.l + hover * slot" :y="PAD.t" :width="slot"
            :height="H - PAD.t - PAD.b" class="bars-hi" />
      <g v-for="(c, i) in cols" :key="c.t" :opacity="hover === null || hover === i ? 1 : 0.55">
        <rect v-for="(s, j) in c.segs" :key="j" :x="c.x" :y="s.y" :width="c.w" :height="s.h"
              :fill="s.colour" shape-rendering="crispEdges" />
      </g>
      <text v-for="t in xTicks" :key="t.x" :x="t.x" :y="H - 6" text-anchor="middle"
            class="bars-lb">{{ t.label }}</text>
    </svg>
  </div>
</template>

<style>
.bars svg { display: block; width: 100%; height: auto; }
.bars-grid { stroke: var(--b-edge-soft); stroke-width: 1; }
.bars-lb { fill: var(--b-ink-4); font: 500 12px var(--b-ui); }
.bars-hi { fill: var(--b-hover); }
.bars-read {
  display: flex; flex-wrap: wrap; gap: 4px 16px; min-height: 20px; margin-bottom: 8px;
  font: 500 var(--b-cap)/1.5 var(--b-ui); color: var(--b-ink-3);
}
.bars-read b { color: var(--b-ink); font-weight: 600; }
.bars-read span { display: inline-flex; align-items: center; gap: 6px; }
.bars-read i { width: 9px; height: 9px; border-radius: 2px; display: block; }
.bars-read u { text-decoration: none; color: var(--b-ink); font-variant-numeric: tabular-nums; }
</style>
