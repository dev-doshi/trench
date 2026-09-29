<script setup lang="ts">
/* A share of a whole: a ring and, beside it, the same parts as a ranked list
 * with their counts. The ring gives the proportion at a glance; the list is
 * what gets read. Hovering either one highlights the part in both. */
import { computed, ref } from "vue";

export interface Part { name: string; value: number; colour: string }

const props = defineProps<{ parts: Part[]; unit?: string }>();

const R = 42;
const C = 2 * Math.PI * R;
const total = computed(() => props.parts.reduce((a, p) => a + p.value, 0));
const on = ref<string | null>(null);

const arcs = computed(() => {
  const gap = props.parts.filter((p) => p.value).length > 1 ? 1.2 : 0;
  let at = 0;
  return props.parts.filter((p) => p.value).map((p) => {
    const len = (p.value / Math.max(1, total.value)) * C;
    const a = { name: p.name, colour: p.colour, dash: `${Math.max(0.01, len - gap)} ${C}`, off: -at };
    at += len;
    return a;
  });
});
const pct = (v: number) => {
  const p = (v / Math.max(1, total.value)) * 100;
  return p >= 10 || p === 0 ? `${Math.round(p)}%` : `${p.toFixed(1)}%`;
};
const centre = computed(() => {
  const p = props.parts.find((x) => x.name === on.value);
  return p ? { v: pct(p.value), l: p.name } : { v: total.value.toLocaleString(), l: props.unit || "total" };
});
</script>

<template>
  <div class="dn">
    <svg viewBox="0 0 100 100" class="dn-ring" role="img" aria-label="Share of the total">
      <circle cx="50" cy="50" :r="R" class="dn-track" />
      <circle v-for="a in arcs" :key="a.name" cx="50" cy="50" :r="R" fill="none"
              :stroke="a.colour" stroke-width="11" :stroke-dasharray="a.dash"
              :stroke-dashoffset="a.off" transform="rotate(-90 50 50)"
              :opacity="on && on !== a.name ? 0.3 : 1"
              @mouseenter="on = a.name" @mouseleave="on = null" />
      <text x="50" y="50" text-anchor="middle" class="dn-v">{{ centre.v }}</text>
      <text x="50" y="62" text-anchor="middle" class="dn-l">{{ centre.l }}</text>
    </svg>
    <ul class="dn-list">
      <li v-for="p in parts" :key="p.name" :class="{ dim: on && on !== p.name }"
          @mouseenter="on = p.name" @mouseleave="on = null">
        <i :style="{ background: p.colour }" />
        <span class="dn-n" :title="p.name">{{ p.name }}</span>
        <u>{{ p.value.toLocaleString() }}</u>
        <s>{{ pct(p.value) }}</s>
      </li>
    </ul>
  </div>
</template>

<style>
.dn { display: flex; flex-wrap: wrap; align-items: center; justify-content: center; gap: 20px; }
.dn-ring { width: 132px; height: 132px; flex: none; }
.dn-ring circle { transition: opacity .12s; }
.dn-track { fill: none; stroke: var(--b-edge-soft); stroke-width: 11; }
.dn-v { fill: var(--b-ink); font: 600 15px var(--b-ui); font-variant-numeric: tabular-nums; }
.dn-l { fill: var(--b-ink-4); font: 500 8.5px var(--b-ui); }
.dn-list { list-style: none; margin: 0; padding: 0; flex: 1; min-width: 170px; display: grid; gap: 2px; }
.dn-list li {
  display: grid; grid-template-columns: 10px minmax(0, 1fr) auto 44px; align-items: center;
  gap: 8px; padding: 3px 0; font: 500 var(--b-ui-s)/1.3 var(--b-ui); color: var(--b-ink-2);
  transition: opacity .12s;
}
.dn-list li.dim { opacity: .45; }
.dn-list i { width: 10px; height: 10px; border-radius: 3px; }
.dn-n { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dn-list u { text-decoration: none; color: var(--b-ink); font-variant-numeric: tabular-nums; }
.dn-list s { text-decoration: none; text-align: right; color: var(--b-ink-4);
  font-size: var(--b-cap); font-variant-numeric: tabular-nums; }
</style>
