<script setup lang="ts">
/* The spine: one mark carrying both how much and what kind.
 *
 * A row in a column has to answer two questions — how big is this compared with
 * its neighbours, and what happened inside it. The conventional answers are a
 * number plus a percentage, or worse, a number plus a donut. Both make you read
 * two things and do arithmetic.
 *
 * So: the bar's *length* is the row's volume against the largest row in the
 * column, and the bar's *segments* are the outcome split within it. Length
 * compares across rows; segmentation reads within one. Nothing needs a legend
 * because the panel beside it names the same fills in the same order.
 *
 * 3px tall, because it sits under an identifier and must not compete with it.
 * A segment thinner than half a pixel is dropped rather than rounded up to one —
 * inflating a single query into a visible band is a lie at the scale that
 * matters most, which is a column of two thousand rows where one of them failed.
 */
import { computed } from "vue";
import { KINDS, type Kind } from "../lib/outcome";

const props = defineProps<{
  by: Record<Kind, number>;
  total: number;
  /** the largest total in this column, so lengths are comparable */
  max: number;
}>();

const W = 100;   // viewBox units; the element is stretched by CSS

const segs = computed(() => {
  const len = props.max > 0 ? (props.total / props.max) * W : 0;
  const out: { kind: Kind; x: number; w: number }[] = [];
  let x = 0;
  for (const k of KINDS) {
    const n = props.by[k];
    if (!n) continue;
    const w = (n / Math.max(1, props.total)) * len;
    if (w < 0.05) continue;          // below half a device pixel: do not fake it
    out.push({ kind: k, x, w });
    x += w;
  }
  return out;
});
</script>

<template>
  <svg class="sp" viewBox="0 0 100 3" preserveAspectRatio="none" aria-hidden="true">
    <rect v-for="s in segs" :key="s.kind" :x="s.x" y="0" :width="s.w" height="3"
          :class="s.kind === 'unknown' ? 'sp-unknown' : ''"
          :fill="s.kind === 'unknown' ? 'none' : `var(--o-${s.kind})`" />
  </svg>
</template>
