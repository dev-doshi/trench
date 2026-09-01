<script setup lang="ts">
/* Time to answer, as a distribution on a log axis.
 *
 * Latency is the one measurement in DNS where an average is actively misleading:
 * a cache hit is 0.1ms, a cold DoT lookup is 90ms, a timeout is 4000ms, and the
 * mean of those describes nothing that ever happened. So this shows the shape —
 * p50 to p95 as a bar, p99 as a separate mark — on a logarithmic axis, because a
 * linear axis compresses every cache hit onto the zero line and spends four
 * fifths of its width on the timeouts.
 *
 * The axis labels are HTML positioned by percentage, not SVG text. The strip is
 * stretched to whatever width its column happens to be, and an SVG stretched on
 * one axis stretches the glyphs with it — which is exactly why the previous
 * version was unreadable at every size it actually rendered at.
 */
import { computed, ref } from "vue";

const props = defineProps<{ p50: number; p95: number; p99: number }>();

const LO = 0.05, HI = 5000;       // ms; a cache hit through to a dead upstream

/** position on the axis, 0–100% */
const pos = (ms: number) => {
  const v = Math.min(HI, Math.max(LO, ms || LO));
  return (Math.log10(v / LO) / Math.log10(HI / LO)) * 100;
};
/** the inverse, for reading a value back out of a cursor position */
const at = (pct: number) => LO * Math.pow(HI / LO, Math.min(1, Math.max(0, pct / 100)));

const fmt = (ms: number) =>
  ms < 1 ? `${Math.round(ms * 1000)} µs`
  : ms >= 1000 ? `${(ms / 1000).toFixed(1)} s`
  : `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;

const decades = computed(() =>
  [0.1, 1, 10, 100, 1000].map((ms) => ({ pct: pos(ms), label: fmt(ms) })));

const bar = computed(() => {
  const a = pos(props.p50), b = pos(props.p95);
  return { left: a, width: Math.max(0.8, b - a) };
});
const empty = computed(() => !props.p50 && !props.p95 && !props.p99);

const hover = ref<number | null>(null);
function track(e: MouseEvent) {
  const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
  hover.value = ((e.clientX - r.left) / r.width) * 100;
}
const reading = computed(() => (hover.value === null ? null : fmt(at(hover.value))));
</script>

<template>
  <div class="pct">
    <div class="pct-plot" @mousemove="track" @mouseleave="hover = null">
      <i v-for="d in decades" :key="d.pct" class="pct-grid" :style="{ left: d.pct + '%' }" />
      <template v-if="!empty">
        <span class="pct-lane" />
        <span class="pct-bar" :style="{ left: bar.left + '%', width: bar.width + '%' }" />
        <span class="pct-p99" :style="{ left: pos(p99) + '%' }" />
      </template>
      <span class="pct-cur" v-if="hover !== null" :style="{ left: hover + '%' }" />
    </div>

    <div class="pct-axis">
      <span v-for="d in decades" :key="'a' + d.pct" :style="{ left: d.pct + '%' }">{{ d.label }}</span>
    </div>

    <div class="pct-key" v-if="!empty">
      <span><i class="sw bar" />p50–p95 <u>{{ fmt(p50) }} – {{ fmt(p95) }}</u></span>
      <span><i class="sw p99" />p99 <u>{{ fmt(p99) }}</u></span>
      <span class="pct-read" v-if="reading">at cursor <u>{{ reading }}</u></span>
    </div>
    <p class="b-void-state" style="padding:var(--b-2) 0" v-else>
      Nothing here took measurable time.
    </p>
  </div>
</template>
