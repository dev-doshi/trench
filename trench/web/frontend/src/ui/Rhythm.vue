<script setup lang="ts">
/* Day-of-week × hour, as a grid of 168 cells.
 *
 * This is the one place a matrix is genuinely the best chart rather than a
 * fallback. The question it answers — "when does this happen, and is that
 * normal for this time of week" — is inherently two-dimensional and cyclic, and
 * a line chart destroys it by unrolling the cycle into a straight line where
 * Tuesday 3am sits nowhere near Wednesday 3am.
 *
 * Choices that are not the default ones:
 *   · a *sequential* ink ramp, not a rainbow. Rainbow scales imply ordered
 *     categories where there is only magnitude, and they make two adjacent
 *     values look like different kinds of thing
 *   · the ramp is perceptually spaced by taking the square root of the
 *     normalised value: query volume is heavily skewed, so a linear ramp paints
 *     161 cells the same shade and three cells bright
 *   · zero is drawn as an empty cell with a hairline, not as the darkest step of
 *     the ramp. "Nothing happened" and "very little happened" are different
 *     facts and must not share an appearance
 *   · hours are labelled every three, days by initial, and the labels sit
 *     outside the grid so no cell is obscured
 */
import { computed } from "vue";

const props = defineProps<{
  /** [dayOfWeek 0=Sun, hour 0-23, value] */
  cells: [number, number, number][];
  unit?: string;
}>();

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const grid = computed(() => {
  const g: number[][] = Array.from({ length: 7 }, () => new Array(24).fill(0));
  for (const [d, h, v] of props.cells) {
    if (d >= 0 && d < 7 && h >= 0 && h < 24) g[d][h] = v;
  }
  return g;
});

const peak = computed(() => Math.max(1, ...props.cells.map((c) => c[2])));

/* Five steps of ink. Fewer than five and the pattern flattens; more than five
 * and the reader cannot tell two adjacent steps apart anyway. */
const STEPS = ["#2b2b32", "#454550", "#6a6a76", "#9c9ba4", "#e8e7e4"];

function fill(v: number): string {
  if (!v) return "transparent";
  const t = Math.sqrt(v / peak.value);              // skew correction
  return STEPS[Math.min(STEPS.length - 1, Math.floor(t * STEPS.length))];
}

const nf = new Intl.NumberFormat();
</script>

<template>
  <div>
    <div class="rhy">
      <span />
      <span class="hh" v-for="h in 24" :key="'h' + h">{{ (h - 1) % 3 === 0 ? h - 1 : "" }}</span>
      <template v-for="(row, d) in grid" :key="d">
        <span class="dd">{{ DAYS[d].slice(0, 2) }}</span>
        <span v-for="(v, h) in row" :key="h" class="cell"
              :style="{ background: fill(v), boxShadow: v ? 'none' : 'inset 0 0 0 1px var(--b-edge-soft)' }"
              :title="`${DAYS[d]} ${String(h).padStart(2, '0')}:00 — ${nf.format(v)}${unit ? ' ' + unit : ''}`" />
      </template>
    </div>
    <div class="mtr-l">
      <span class="b-cap">less</span>
      <span class="ribbon" style="width:120px;height:8px">
        <i v-for="s in STEPS" :key="s" :style="{ background: s }" />
      </span>
      <span class="b-cap">more — peak {{ nf.format(peak) }}{{ unit ? " " + unit : "" }}</span>
      <span class="b-cap" style="margin-left:12px">
        an outlined cell is nothing at all, not a small amount
      </span>
    </div>
  </div>
</template>
