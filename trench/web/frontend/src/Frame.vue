<script setup lang="ts">
/* The frame: wordmark, where you can go, whether the resolver is answering.
 *
 * These were behind a menu, on the argument that a row of tabs asserts every
 * screen is equally important. In use that cost more than it saved: every move
 * was a click to open, a read, and a click to choose, and you could not see
 * where you were relative to anywhere else. The destinations are visible now.
 *
 * Appearance is *not* here. It is a preference set once, not a control worth a
 * permanent seat in the most valuable strip of the window; it lives in Settings.
 *
 * The wordmark is a caliper's two scales, offset. It is the instrument the
 * product is named for and the only drawn ornament anywhere in the interface.
 */
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { api } from "./lib/api";
import { local } from "./lib/local";
import { store } from "./lib/store";
import Ico from "./ui/Ico.vue";
import Palette from "./ui/Palette.vue";
import Inspector from "./ui/Inspector.vue";

const route = useRoute();
const pal = ref<InstanceType<typeof Palette> | null>(null);
const open = ref(false);
const s = store.state;

/* Grouped by what the operator is doing, not by which subsystem owns the code. */
const PLACES = [
  { group: "Look", items: [
    { to: "/", name: "Browse", of: "Group the traffic by anything, then by anything" },
    { to: "/live", name: "Live", of: "Rates and the tape, as answers arrive" },
    { to: "/log", name: "Log", of: "The rows themselves, for reading and export" },
    { to: "/history", name: "History", of: "Aggregate over the whole retained log" },
  ] },
  { group: "Decide", items: [
    { to: "/policy", name: "Policy", of: "Your rules, read back by what they do" },
    { to: "/breakage", name: "Breakage", of: "Refusals that look like something stuck" },
    { to: "/devices", name: "Devices", of: "Who is asking, and what each one is like" },
  ] },
  { group: "Account for", items: [
    { to: "/resolver", name: "Resolver", of: "Where answers come from, and what they cost" },
    { to: "/privacy", name: "Privacy", of: "What is remembered, and what leaves" },
    { to: "/audit", name: "Audit", of: "Who changed what, and when" },
    { to: "/settings", name: "Settings", of: "The few things a browser should own" },
  ] },
];

const FLAT = PLACES.flatMap((g) => g.items);

const state = computed(() => ({
  live: { label: "answering", cls: "ok" },
  connecting: { label: "connecting", cls: "" },
  reconnecting: { label: "not answering", cls: "bad" },
  offline: { label: "offline", cls: "bad" },
}[s.conn]));



onMounted(() => {
  document.documentElement.dataset.skin = local.get("bw_skin") || "auto";
});

/** The shortcut as this keyboard spells it: ⌘K on a Mac, Ctrl K elsewhere. */
const mod = /Mac|iP(hone|ad|od)/.test(navigator.platform || navigator.userAgent) ? "⌘K" : "Ctrl K";

/** The place sheet: `g` or the Places button. Focus goes into it on open and
 *  back to whatever opened it on close, so the keyboard never loses its place. */
const sheet = ref<HTMLElement | null>(null);
let opener: HTMLElement | null = null;
async function setOpen(v: boolean) {
  if (v === open.value) return;
  if (v) opener = document.activeElement as HTMLElement | null;
  open.value = v;
  if (v) {
    await nextTick();
    (sheet.value?.querySelector("a.on") as HTMLElement | null
      ?? sheet.value?.querySelector("a") as HTMLElement | null)?.focus();
  } else {
    opener?.focus?.();
    opener = null;
  }
}
watch(() => route.path, () => { if (open.value) { opener = null; open.value = false; } });

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape" && open.value) { setOpen(false); e.preventDefault(); return; }
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target as HTMLElement | null;
  if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT"
            || t.isContentEditable)) return;
  if (e.key === "g") { setOpen(!open.value); e.preventDefault(); }
}
onMounted(() => window.addEventListener("keydown", onKey));
onUnmounted(() => window.removeEventListener("keydown", onKey));

async function signOut() {
  await api.post("/auth/logout").catch(() => {});
  store.stopWs();
  store.setUser(null);
}
</script>

<template>
  <div>
    <a class="b-skip" href="#main">Skip to content</a>
    <header class="bframe">
      <div class="bframe-mark">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <g stroke="var(--b-ink)" stroke-width="1.4">
            <path d="M2.5 8.5h19" />
            <path d="M5 8.5V4.5M9 8.5V3.5M13 8.5V4.5M17 8.5V3.5M21 8.5V4.5" />
          </g>
          <g stroke="var(--b-ink-3)" stroke-width="1.4">
            <path d="M3.7 15.5h19" />
            <path d="M6.2 15.5v4M10.2 15.5v5M14.2 15.5v4M18.2 15.5v5M22.2 15.5v4" />
          </g>
        </svg>
        <b>Bailiwick</b><i>trench</i>
      </div>
      <div class="bframe-sep" />

      <nav class="bframe-nav" aria-label="Places">
        <RouterLink v-for="i in FLAT" :key="i.to" :to="i.to" :class="{ on: i.to === route.path }"
                    :aria-current="i.to === route.path ? 'page' : undefined"
                    :title="i.of">{{ i.name }}</RouterLink>
      </nav>
      <button class="bframe-btn bframe-places" @click="setOpen(true)"
              aria-haspopup="dialog" :aria-expanded="open" title="All places (g)">
        <Ico name="list" :size="15" /> <span class="lbl">{{ FLAT.find((i) => i.to === route.path)?.name || "Places" }}</span>
      </button>

      <div class="bframe-grow" />

      <button class="bframe-btn" @click="pal?.show()" :aria-keyshortcuts="mod === '⌘K' ? 'Meta+K' : 'Control+K'">
        <Ico name="find" :size="15" /> <span class="lbl">Search</span> <kbd>{{ mod }}</kbd>
      </button>
      <div class="bframe-state" :class="state.cls" role="status"
           :title="state.cls === 'bad' ? 'The live feed is down; it reconnects by itself.' : undefined">
        <span class="led" aria-hidden="true" /><span class="lbl">{{ state.label }}</span>
      </div>
      <div class="bframe-sep" />
      <button class="bframe-btn" @click="signOut">Sign out</button>
    </header>

    <div class="bsheet" v-if="open" @click.self="setOpen(false)">
      <nav class="bsheet-in" ref="sheet" role="dialog" aria-modal="true" aria-label="All places">
        <template v-for="g in PLACES" :key="g.group">
          <h4 class="b-cap">{{ g.group }}</h4>
          <RouterLink v-for="i in g.items" :key="i.to" :to="i.to" :class="{ on: i.to === route.path }"
                      :aria-current="i.to === route.path ? 'page' : undefined">
            <b>{{ i.name }}</b><em>{{ i.of }}</em>
          </RouterLink>
        </template>
      </nav>
    </div>

    <!-- every view owns its own scrolling and padding, so there is no wrapper -->
    <main id="main" tabindex="-1">
      <RouterView />
    </main>

    <Palette ref="pal" />
    <Inspector />
  </div>
</template>
