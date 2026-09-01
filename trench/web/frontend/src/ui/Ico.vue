<script setup lang="ts">
/* The icon set. Drawn for this product, on one grid, with one set of rules.
 *
 * Rules, applied to every glyph without exception:
 *   · 16×16 box, 1px padding, so shapes live on a 14px field
 *   · 1.5px stroke, butt caps, mitre joins — a mechanical hand, not a friendly
 *     one. Round caps read as consumer software
 *   · geometry only: no glyph contains a curve that is not a circle or an arc
 *     of one, and no glyph contains text
 *   · every shape lands on a half-pixel so a 1.5px stroke stays crisp at 16px
 *
 * Two things this set deliberately does not do. It does not use an emoji or a
 * typographic symbol standing in for an icon — a "⚙" is a character from a font
 * you do not control, at a size and weight you did not choose. And it does not
 * reach for the conventional metaphor when the conventional metaphor is wrong:
 * the facet-order control is three bars of decreasing width (levels of a
 * grouping) rather than a funnel, because nothing is being filtered out; the
 * time window is a caliper rather than a clock, because it is a measured span
 * and not a moment.
 */
const props = withDefaults(defineProps<{ name: string; size?: number }>(), { size: 16 });

/* Paths are authored as a list so the shape rules above are checkable by
 * reading one place. Each entry is stroked unless it names a fill. */
const G: Record<string, { d?: string[]; fill?: string[]; circle?: [number, number, number][] }> = {
  // disclosure: drill into this level
  next: { d: ["M6.5 3.5 L11 8 L6.5 12.5"] },
  down: { d: ["M3.5 6.5 L8 11 L12.5 6.5"] },
  up: { d: ["M3.5 9.5 L8 5 L12.5 9.5"] },
  back: { d: ["M9.5 3.5 L5 8 L9.5 12.5"] },

  // the grouping order: levels of decreasing extent, not a funnel
  levels: { d: ["M2.5 4.5 H13.5", "M2.5 8 H10.5", "M2.5 11.5 H7.5"] },

  // sort direction: a stack with an arrow
  sort: { d: ["M3.5 4.5 H9.5", "M3.5 8 H7.5", "M3.5 11.5 H5.5", "M11.5 5 V12", "M9.5 10 L11.5 12 L13.5 10"] },

  // a measured span, not a clock
  span: { d: ["M2.5 4 V12", "M13.5 4 V12", "M2.5 8 H13.5"] },

  // a client: a terminal outline with a stand. Not a laptop, not a phone —
  // most of these devices are neither
  device: { d: ["M2.5 3.5 H13.5 V10.5 H2.5 Z", "M6 12.5 H10"] },

  // a matched pattern: a bracketed expression with the match inside
  rule: { d: ["M5 3.5 H3.5 V12.5 H5", "M11 3.5 H12.5 V12.5 H11"], fill: ["M7 7 H9 V9 H7 Z"] },

  // a list of rules, as a source
  list: { d: ["M5.5 4.5 H13.5", "M5.5 8 H13.5", "M5.5 11.5 H13.5"], fill: ["M2.5 3.75 H4 V5.25 H2.5 Z", "M2.5 7.25 H4 V8.75 H2.5 Z", "M2.5 10.75 H4 V12.25 H2.5 Z"] },

  // search: the convention, and the convention is right here
  find: { circle: [[7, 7, 4]], d: ["M10 10 L13.5 13.5"] },

  // copy: two planes, offset
  copy: { d: ["M5.5 5.5 H12.5 V12.5 H5.5 Z", "M3.5 10.5 V3.5 H10.5"] },

  // pin a selection in place
  pin: { circle: [[8, 6, 2.5]], d: ["M8 8.5 V13"] },

  // leaves this machine

  // close
  shut: { d: ["M4 4 L12 12", "M12 4 L4 12"] },

  // an accepted state
  kept: { d: ["M3.5 8.5 L6.5 11.5 L12.5 5"] },

  // blocked: a circle with a bar. Not a "no entry" sign, not a shield
  held: { circle: [[8, 8, 5]], d: ["M5 8 H11"] },

  // trouble: a stem that breaks
  broke: { d: ["M8 2.5 V6.5", "M8 9.5 V13.5", "M5.5 8 H10.5"] },

  // the resolver itself: a hub with three peers
  resolver: { circle: [[8, 8, 2]], d: ["M8 2.5 V6", "M3.5 11 L6.3 9.2", "M12.5 11 L9.7 9.2"] },
};

const g = () => G[props.name] || G.next;
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 16 16" fill="none" aria-hidden="true"
       class="ico">
    <g stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter">
      <path v-for="(d, i) in (g().d || [])" :key="'d' + i" :d="d" />
      <circle v-for="(c, i) in (g().circle || [])" :key="'c' + i"
              :cx="c[0]" :cy="c[1]" :r="c[2]" />
    </g>
    <g fill="currentColor">
      <path v-for="(d, i) in (g().fill || [])" :key="'f' + i" :d="d" />
    </g>
  </svg>
</template>

<style>
.ico { display: block; flex: none; }
</style>
