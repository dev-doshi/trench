<script setup lang="ts">
// Global command palette (⌘K / Ctrl-K). Jumps to views; when the query looks
// like a domain or IP, offers live-activity + query-log searches for it.
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api } from "../lib/api";
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
async function op(path: string, msg: string) {
  try { await api.post(path); store.toast(msg); }
  catch (e: any) { store.toast("Action failed", e.message, true); }
}
const ACTIONS = [
  { icon: "held", title: "Toggle filtering", sub: "pause/resume filtering", run: () => op("/toggle", "Blocking toggled") },
  { icon: "broke", title: "Flush DNS cache", sub: "drop all cached answers", run: () => op("/cache/flush", "Cache flushed") },
  { icon: "resolver", title: "Refresh blocklists", sub: "re-download gravity sources", run: () => op("/gravity/refresh", "Blocklist refresh started") },
  { icon: "span", title: store.state.paused ? "Resume live feed" : "Pause live feed", sub: "activity stream", run: () => store.togglePause() },
];

const results = computed(() => {
  const t = q.value.trim().toLowerCase();
  const out: any[] = [];
  if (t && /[.:]/.test(t)) {
    const isIp = /^[0-9a-f.:]+$/.test(t);
    out.push({ icon: "find", title: `Inspect ${isIp ? "client" : "domain"} “${q.value}”`, tag: "inspect", act: () => store.inspect(isIp ? "client" : "domain", q.value.trim()) });
    out.push({ icon: "list", title: `Search query log for “${q.value}”`, tag: "search", act: () => router.push("/log?q=" + encodeURIComponent("name=" + q.value.trim().toLowerCase())) });
  }
  for (const n of NAV) {
    if (!t || n.title.toLowerCase().includes(t) || n.sub.toLowerCase().includes(t))
      out.push({ icon: n.icon, title: n.title, sub: n.sub, tag: "go", act: () => router.push(n.to) });
  }
  for (const a of ACTIONS) {
    if (!t || a.title.toLowerCase().includes(t) || a.sub.toLowerCase().includes(t))
      out.push({ icon: a.icon, title: a.title, sub: a.sub, tag: "run", act: a.run });
  }
  return out;
});

watch(q, () => (sel.value = 0));

function show() {
  open.value = true; q.value = ""; sel.value = 0;
  nextTick(() => input.value?.focus());
}
function hide() { open.value = false; }
function run(r: any) { r.act(); hide(); }

function onKey(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); open.value ? hide() : show(); return; }
  if (!open.value) return;
  if (e.key === "Escape") hide();
  else if (e.key === "ArrowDown") { e.preventDefault(); sel.value = Math.min(sel.value + 1, results.value.length - 1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); sel.value = Math.max(sel.value - 1, 0); }
  else if (e.key === "Enter" && results.value[sel.value]) run(results.value[sel.value]);
}
window.addEventListener("keydown", onKey);
onBeforeUnmount(() => window.removeEventListener("keydown", onKey));
defineExpose({ show });
</script>

<template>
  <Transition name="fade">
    <div v-if="open" class="pal-bg" @mousedown.self="hide">
      <div class="pal">
        <input ref="input" v-model="q" placeholder="Search views, or type a domain / client IP…" spellcheck="false" />
        <div class="results">
          <div v-for="(r, i) in results" :key="i" class="res" :class="{ sel: i === sel }"
               @mouseenter="sel = i" @click="run(r)">
            <span class="ic"><Ico :name="r.icon" /></span>
            <span class="tt">{{ r.title }}<small v-if="r.sub">{{ r.sub }}</small></span>
            <span class="tag">{{ r.tag }}</span>
          </div>
        </div>
      </div>
    </div>
  </Transition>
</template>
