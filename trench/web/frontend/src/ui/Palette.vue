<script setup lang="ts">
// Global command palette (⌘K / Ctrl-K). Jumps to views; when the query looks
// like a domain or IP, offers live-activity + query-log searches for it.
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api } from "../lib/api";
import { term } from "../lib/qlang";
import { store } from "../lib/store";
import Ico from "./Ico.vue";

const open = ref(false);
const q = ref("");
const sel = ref(0);
const input = ref<HTMLInputElement | null>(null);
const router = useRouter();

const NAV = [
  { icon: "levels", title: "Browse", sub: "Group traffic by anything, then by anything", to: "/" },
  { icon: "span", title: "Live", sub: "Rates and the tape", to: "/live" },
  { icon: "list", title: "Log", sub: "The rows themselves", to: "/log" },
  { icon: "levels", title: "History", sub: "Aggregate over the retained log", to: "/history" },
  { icon: "rule", title: "Policy", sub: "Your rules and what they do", to: "/policy" },
  { icon: "broke", title: "Breakage", sub: "Blocks that look like something stuck", to: "/breakage" },
  { icon: "device", title: "Devices", sub: "Who is asking", to: "/devices" },
  { icon: "resolver", title: "Resolver", sub: "Upstreams, cache, latency", to: "/resolver" },
  { icon: "held", title: "Privacy", sub: "What is remembered", to: "/privacy" },
  { icon: "list", title: "Audit", sub: "Who changed what", to: "/audit" },
  { icon: "sort", title: "Settings", sub: "Browser and API access", to: "/settings" },
];

// ops actions runnable straight from the palette
async function op(path: string, msg: string | ((r: any) => string)) {
  try {
    const r = await api.post(path);
    store.toast(typeof msg === "string" ? msg : msg(r));
  } catch (e: any) { store.toast("Action failed", e.message, true); }
}
/** Computed, so the labels say what the action will do *now* — a pause entry
 *  that still says "Pause" while paused is a toggle you have to test to read. */
const ACTIONS = computed(() => [
  { icon: "held", title: store.state.stats?.enabled === false ? "Resume filtering" : "Pause filtering",
    sub: "every device, until switched back",
    run: () => op("/toggle", (r) => (r?.enabled ? "Filtering is on" : "Filtering is off — every name resolves")) },
  { icon: "broke", title: "Flush DNS cache", sub: "drop all cached answers", run: () => op("/cache/flush", "Cache flushed") },
  { icon: "resolver", title: "Refresh blocklists", sub: "re-download every list", run: () => op("/gravity/refresh", "Blocklist refresh started") },
  { icon: "span", title: store.state.paused ? "Resume the live tape" : "Pause the live tape", sub: "this browser only", run: () => store.togglePause() },
]);

const results = computed(() => {
  const t = q.value.trim().toLowerCase();
  const out: any[] = [];
  if (t && /[.:]/.test(t)) {
    const isIp = /^[0-9a-f.:]+$/.test(t);
    out.push({ icon: "find", title: `Inspect ${isIp ? "client" : "domain"} “${q.value}”`, tag: "inspect", act: () => store.inspect(isIp ? "client" : "domain", q.value.trim()) });
    out.push({ icon: "list", title: `Search query log for “${q.value}”`, tag: "search", act: () => router.push("/log?q=" + encodeURIComponent(term("name", q.value.trim().toLowerCase(), ":"))) });
  }
  for (const n of NAV) {
    if (!t || n.title.toLowerCase().includes(t) || n.sub.toLowerCase().includes(t))
      out.push({ icon: n.icon, title: n.title, sub: n.sub, tag: "go", act: () => router.push(n.to) });
  }
  for (const a of ACTIONS.value) {
    if (!t || a.title.toLowerCase().includes(t) || a.sub.toLowerCase().includes(t))
      out.push({ icon: a.icon, title: a.title, sub: a.sub, tag: "run", act: a.run });
  }
  return out;
});

watch(q, () => (sel.value = 0));
const list = ref<HTMLElement | null>(null);
watch(sel, () => nextTick(() =>
  list.value?.querySelector(".res.sel")?.scrollIntoView({ block: "nearest" })));

let opener: HTMLElement | null = null;
function show() {
  opener = document.activeElement as HTMLElement | null;
  open.value = true; q.value = ""; sel.value = 0;
  nextTick(() => input.value?.focus());
}
/** `back` is false when the chosen action moved focus somewhere on purpose
 *  (a navigation, the inspector) — handing it back would undo that. */
function hide(back = true) {
  open.value = false;
  if (back) opener?.focus?.();
  opener = null;
}
function run(r: any) { hide(r.tag === "run"); r.act(); }

function onKey(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k") {
    e.preventDefault(); open.value ? hide() : show(); return;
  }
  if (!open.value || e.isComposing) return;
  const n = results.value.length;
  if (e.key === "Escape") { e.preventDefault(); hide(); }
  else if (e.key === "ArrowDown") { e.preventDefault(); if (n) sel.value = (sel.value + 1) % n; }
  else if (e.key === "ArrowUp") { e.preventDefault(); if (n) sel.value = (sel.value - 1 + n) % n; }
  else if (e.key === "Home" && e.target !== input.value) { e.preventDefault(); sel.value = 0; }
  else if (e.key === "End" && e.target !== input.value) { e.preventDefault(); sel.value = Math.max(0, n - 1); }
  else if (e.key === "Enter" && results.value[sel.value]) { e.preventDefault(); run(results.value[sel.value]); }
  else if (e.key === "Tab") e.preventDefault();   // the palette is modal; focus stays in it
}
window.addEventListener("keydown", onKey);
onBeforeUnmount(() => window.removeEventListener("keydown", onKey));
defineExpose({ show });
</script>

<template>
  <Transition name="fade">
    <div v-if="open" class="pal-bg" @mousedown.self="hide()">
      <div class="pal" role="dialog" aria-modal="true" aria-label="Search and commands">
        <input ref="input" v-model="q" placeholder="Search views, or type a domain / client IP…"
               spellcheck="false" autocomplete="off" role="combobox" aria-expanded="true"
               aria-controls="pal-list" aria-autocomplete="list" aria-label="Search views and commands"
               :aria-activedescendant="results.length ? `pal-${sel}` : undefined" />
        <div class="results" id="pal-list" role="listbox" ref="list" aria-label="Results">
          <div v-for="(r, i) in results" :key="r.tag + r.title" :id="`pal-${i}`" class="res"
               :class="{ sel: i === sel }" role="option" :aria-selected="i === sel"
               @mouseenter="sel = i" @click="run(r)">
            <span class="ic" aria-hidden="true"><Ico :name="r.icon" /></span>
            <span class="tt">{{ r.title }}<small v-if="r.sub">{{ r.sub }}</small></span>
            <span class="tag">{{ r.tag }}</span>
          </div>
          <div class="res" v-if="!results.length" role="presentation">
            <span class="tt">Nothing matches. Type a domain or an address to inspect it.</span>
          </div>
        </div>
      </div>
    </div>
  </Transition>
</template>
