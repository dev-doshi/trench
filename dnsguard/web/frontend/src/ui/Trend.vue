<script setup lang="ts">
/* Multi-series lines, labelled directly at the end of each line.
 *
 * The decision worth defending: there is no legend. A legend makes the reader
 * hold a colour in working memory, travel to the plot, and match it — for every
 * series, every time they look. Putting each name at the end of its own line
 * removes that step, and it is why this is drawn by hand: no charting library
 * does direct labelling well.
 *
 * Consequences that follow from that choice rather than from taste:
 *   · at most six series, because more than six end-labels collide. The caller
 *     ranks; the chart says how many it did not draw
 *   · the right margin is sized from the longest label, in characters
 *   · no area fill — a fill implies the series sum to something, and these are
 *     independent measurements
 *   · no dot per sample: 200 dots is noise. Dots appear only when a series has
 *     so few points that a bare line would be ambiguous
 *   · colour is ink weight in ranked order; the two product hues are used only
 *     when a series *means* blocked or failed
 */
import { computed, ref } from "vue";

export interface Series { name: string; points: [number, number][]; kind?: string }

const props = withDefaults(defineProps<{
  series: Series[];
  height?: number;
}>(), { height: 200 });

const W = 1000;
const PAD = { t: 12, b: 26, l: 48 };
const INK = ["#f4f3f0", "#b9b8b2", "#8d8c86", "#6c6b67", "#55545f", "#43423d"];

function stroke(s: Series, i: number): string {
  if (s.kind === "blocked") return "var(--o-blocked)";
  if (s.kind === "failed") return "var(--o-failed)";
  if (s.kind === "cache") return "var(--o-cache)";
  return INK[i % INK.length];
}

const shown = computed(() => props.series.slice(0, 6));
const dropped = computed(() => Math.max(0, props.series.length - shown.value.length));

/* 6.6px per character at 12px in a system grotesk — measured, not guessed. */
const rightPad = computed(() =>
  Math.min(230, Math.max(4, ...shown.value.map((s) => s.name.length)) * 6.6 + 14));

const bounds = computed(() => {
  let x0 = Infinity, x1 = -Infinity, y1 = 0;
  for (const s of shown.value) {
    for (const [x, y] of s.points) {
      if (x < x0) x0 = x;
      if (x > x1) x1 = x;
      if (y > y1) y1 = y;
    }
  }
  if (!Number.isFinite(x0)) { x0 = 0; x1 = 1; }
  return { x0, x1: x1 === x0 ? x0 + 1 : x1, y1: y1 || 1 };
});

const H = computed(() => props.height);
const px = (x: number) => {
  const { x0, x1 } = bounds.value;
  return PAD.l + ((x - x0) / (x1 - x0)) * (W - PAD.l - rightPad.value);
};
const py = (y: number) => {
  const h = H.value - PAD.t - PAD.b;
  return PAD.t + h - (y / bounds.value.y1) * h;
};

/**
 * Direct labels, pushed apart so they cannot overlap.
 *
 * Limiting the series count is not enough on its own: two series that end at
 * nearly the same value put their labels on top of each other, which is worse
 * than a legend because it is unreadable rather than merely indirect. So the
 * labels are laid out after the lines — sorted by where their line ends, then
 * separated to a minimum spacing, with a leader offset kept so each label still
 * sits nearest its own line.
 */
const LABEL_GAP = 14;

const paths = computed(() => {
  const base = shown.value.map((s, i) => {
    const pts = s.points.slice().sort((a, b) => a[0] - b[0]);
    const d = pts.map(([x, y], j) => `${j ? "L" : "M"}${px(x).toFixed(1)} ${py(y).toFixed(1)}`).join(" ");
    const last = pts[pts.length - 1];
    return {
      name: s.name, d, colour: stroke(s, i),
      dots: pts.length <= 3 ? pts.map(([x, y]) => ({ x: px(x), y: py(y) })) : [],
      lx: last ? px(last[0]) + 8 : PAD.l,
      endY: last ? py(last[1]) : PAD.t,
      ly: 0,
    };
  });

  // lay the labels out top to bottom, never closer together than LABEL_GAP
  const order = base.slice().sort((a, b) => a.endY - b.endY);
  let floor = -Infinity;
  for (const p of order) {
    p.ly = Math.max(p.endY + 4, floor + LABEL_GAP);
    floor = p.ly;
  }
  // if the stack ran past the bottom, lift the whole column back inside
  const overflow = floor - (H.value - PAD.b);
  if (overflow > 0) for (const p of order) p.ly -= overflow;
  return base;
});

/* Three gridlines. More lines is more ink for no more information. */
const yTicks = computed(() => {
  const top = bounds.value.y1;
  const mag = Math.pow(10, Math.floor(Math.log10(top || 1)));
  const r = top / mag;
  const step = (r >= 5 ? 2 : r >= 2 ? 1 : 0.5) * mag;
  const out: { y: number; label: string }[] = [];
  for (let v = 0; v <= top * 1.001; v += step) {
    out.push({
      y: py(v),
      label: v >= 1000 ? `${Math.round(v / 1000)}k` : String(Math.round(v * 10) / 10),
    });
  }
  return out;
});

function stamp(t: number, span: number): string {
  const d = new Date(t * 1000);
  if (span > 3 * 86400) return d.toLocaleDateString([], { month: "short", day: "numeric" });
  if (span > 2 * 3600) return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  // under two hours the minute alone repeats across ticks, so show seconds
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

/* Ticks are de-duplicated by label, not just by position. A short span used to
 * emit six ticks that all formatted to the same "15:00" — six identical labels
 * under an axis, which looks like a rendering fault and tells you nothing. */
const xTicks = computed(() => {
  const { x0, x1 } = bounds.value;
  const span = x1 - x0;
  const out: { x: number; label: string }[] = [];
  const seen = new Set<string>();
  for (let i = 0; i <= 5; i++) {
    const t = x0 + (span * i) / 5;
    const label = stamp(t, span);
    if (seen.has(label)) continue;
    seen.add(label);
    out.push({ x: px(t), label });
  }
  return out;
});

/* ── hover readout ─────────────────────────────────────────────────────────
 * A line chart you cannot query is a picture. Moving across it snaps to the
 * nearest sample and reads every series at that instant, which is the question
 * people actually have ("what happened at 14:20?") rather than the one a
 * tooltip-per-point answers. */
const hoverX = ref<number | null>(null);

const allX = computed(() => {
  const xs = new Set<number>();
  for (const s of shown.value) for (const [x] of s.points) xs.add(x);
  return [...xs].sort((a, b) => a - b);
});

const cursor = computed(() => {
  if (hoverX.value === null || !allX.value.length) return null;
  const { x0, x1 } = bounds.value;
  const frac = (hoverX.value - PAD.l) / (W - PAD.l - rightPad.value);
  const want = x0 + frac * (x1 - x0);
  let best = allX.value[0];
  for (const x of allX.value) if (Math.abs(x - want) < Math.abs(best - want)) best = x;
  const at = shown.value.map((s, i) => {
    const hit = s.points.find(([x]) => x === best);
    return { name: s.name, colour: stroke(s, i), v: hit ? hit[1] : null };
  }).filter((r) => r.v !== null);
  return { t: best, x: px(best), rows: at, label: stamp(best, bounds.value.x1 - bounds.value.x0) };
});

function track(e: MouseEvent) {
  const svg = e.currentTarget as SVGSVGElement;
  const r = svg.getBoundingClientRect();
  hoverX.value = ((e.clientX - r.left) / r.width) * W;
}

const enough = computed(() => allX.value.length >= 2);
</script>

<template>
  <div>
    <svg v-if="enough" class="lines" :viewBox="`0 0 ${W} ${H}`" role="img"
         :aria-label="`${shown.length} series over time`"
         @mousemove="track" @mouseleave="hoverX = null">
      <g>
        <line v-for="t in yTicks" :key="'y' + t.y" :x1="PAD.l" :y1="t.y"
              :x2="W - rightPad" :y2="t.y" class="ax" />
        <text v-for="t in yTicks" :key="'yl' + t.y" :x="PAD.l - 8" :y="t.y + 4"
              class="lb" text-anchor="end">{{ t.label }}</text>
      </g>
      <g>
        <text v-for="t in xTicks" :key="'x' + t.x" :x="t.x" :y="H - 8"
              class="lb" text-anchor="middle">{{ t.label }}</text>
      </g>
      <g fill="none" stroke-width="1.5" stroke-linejoin="round">
        <path v-for="p in paths" :key="p.name" :d="p.d" :stroke="p.colour" />
      </g>
      <g>
        <template v-for="p in paths" :key="'d' + p.name">
          <circle v-for="(c, j) in p.dots" :key="j" :cx="c.x" :cy="c.y" r="2.5" :fill="p.colour" />
        </template>
      </g>
      <g class="nm">
        <text v-for="p in paths" :key="'n' + p.name" :x="p.lx" :y="p.ly" :fill="p.colour">
          {{ p.name }}
        </text>
      </g>
      <g v-if="cursor">
        <line :x1="cursor.x" :y1="PAD.t" :x2="cursor.x" :y2="H - PAD.b" class="cx" />
        <circle v-for="r in cursor.rows" :key="'c' + r.name"
                :cx="cursor.x" :cy="py(r.v as number)" r="3" :fill="r.colour" />
      </g>
    </svg>
    <div class="tr-read" v-if="enough">
      <template v-if="cursor">
      <b>{{ cursor.label }}</b>
      <span v-for="r in cursor.rows" :key="'r' + r.name">
        <i :style="{ background: r.colour }" />{{ r.name }} <u>{{ r.v }}</u>
      </span>
      </template>
    </div>
    <p class="b-void-state" v-if="!enough" style="margin:0">
      One sample so far — a line needs two. Widen the span, or wait for the next
      bucket.
    </p>
    <p class="sec-note" style="margin:6px 0 0" v-if="dropped">
      {{ dropped }} lower-ranked {{ dropped === 1 ? "series" : "series" }} not drawn.
    </p>
  </div>
</template>
