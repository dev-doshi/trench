<script setup lang="ts">
/* A shape, not a chart: no axes, no numbers. It sits under a figure to say
 * whether that figure is rising, falling or spiky. Given `max`, it draws from
 * zero to that, so a column of sparks on one scale can be compared. */
import { computed } from "vue";

const props = defineProps<{ values: number[]; colour: string; max?: number }>();

const d = computed(() => {
  const v = props.values;
  if (v.length < 2) return null;
  const max = props.max ?? Math.max(...v), min = props.max ? 0 : Math.min(...v);
  const range = max - min || 1;
  const pts = v.map((y, i) => [(i / (v.length - 1)) * 100, 26 - ((y - min) / range) * 22]);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`).join(" ");
  return { line, area: `${line} L100 30 L0 30 Z` };
});
</script>

<template>
  <svg v-if="d" class="spk" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true">
    <path :d="d.area" :fill="colour" opacity="0.14" />
    <path :d="d.line" fill="none" :stroke="colour" stroke-width="1.5"
          vector-effect="non-scaling-stroke" stroke-linejoin="round" />
  </svg>
</template>

<style>
.spk { display: block; width: 100%; height: 34px; }
</style>
