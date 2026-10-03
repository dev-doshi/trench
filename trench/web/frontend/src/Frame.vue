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
 * But not every destination earns the strip. Eleven tabs was two rows' worth of
 * words on a laptop and scrolled off on anything narrower, and three of them
 * (History, Breakage, Resolver) are places you go to answer a specific
 * question, not places you watch. They fold under More; the records that are
 * really configuration — Privacy, Audit, Jobs — are tabs of Settings.
 *
 * The one thing that did earn a seat is the jobs indicator: a blocklist build
 * is minutes of the heaviest work the box does, and "why is it slow" or "did
 * my new lists apply" should be answerable without opening anything.
 *
 * Beside it, CPU and memory: the same question ("is the box struggling")
 * answered in two numbers, from the poll that is already running.
 *
 * The wordmark is a caliper's two scales, offset. It is the instrument the
 * product is named for and the only drawn ornament anywhere in the interface.
 */
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { api } from "./lib/api";
import { boxNow, useJobFeed } from "./lib/jobfeed";
import { bytes, headline } from "./lib/jobs";
import { local } from "./lib/local";
import { forgetNames } from "./lib/names";
import { store } from "./lib/store";
import Ico from "./ui/Ico.vue";
import Palette from "./ui/Palette.vue";
import Inspector from "./ui/Inspector.vue";

const route = useRoute();
const pal = ref<InstanceType<typeof Palette> | null>(null);
const open = ref(false);
const s = store.state;

/* Grouped by what the operator is doing, not by which subsystem owns the code.
 * `more` marks the places that fold under More in the strip; the sheet (`g`)
 * still lists everything, including the Settings tabs worth going to directly. */
const PLACES = [
  { group: "Look", items: [
    { to: "/", name: "Overview", of: "The last day at a glance" },
    { to: "/browse", name: "Browse", of: "Group the traffic by anything, then by anything" },
    { to: "/live", name: "Live", of: "Rates and the tape, as answers arrive" },
    { to: "/log", name: "Log", of: "The rows themselves, for reading and export" },
    { to: "/history", name: "History", of: "Aggregate over the whole retained log", more: true },
  ] },
  { group: "Decide", items: [
    { to: "/policy", name: "Policy", of: "Your rules, read back by what they do" },
    { to: "/devices", name: "Devices", of: "Who is asking, and which group each is in" },
    { to: "/breakage", name: "Breakage", of: "Refusals that look like something stuck", more: true },
  ] },
  { group: "Account for", items: [
    { to: "/resolver", name: "Resolver", of: "Where answers come from, and what they cost", more: true },
    { to: "/settings", name: "Settings", of: "Every knob, plus jobs, privacy and the audit trail" },
    { to: "/settings?tab=jobs", name: "Jobs", of: "List builds, schedules, memory — run one now", sub: true },
    { to: "/settings?tab=privacy", name: "Privacy", of: "What is remembered, and what leaves", sub: true },
    { to: "/settings?tab=audit", name: "Audit", of: "Who changed what, and when", sub: true },
  ] },
];

const ALL = PLACES.flatMap((g) => g.items) as
  { to: string; name: string; of: string; more?: boolean; sub?: boolean }[];
const FLAT = ALL.filter((i) => !i.more && !i.sub);
const MORE = ALL.filter((i) => i.more);
const SUBTABS = ALL.filter((i) => i.sub).map((i) => i.to.split("tab=")[1]);
/** Is `to` where we are? A Settings tab listed on its own counts as its own place. */
function here(to: string): boolean {
  const [path, q] = to.split("?");
  if (path !== route.path) return false;
  const tab = String(route.query.tab || "");
  return q ? tab === q.replace("tab=", "") : !SUBTABS.includes(tab);
}
const moreHere = computed(() => MORE.find((i) => i.to === route.path));

/* More: a small menu, not a second sheet. */
const moreOpen = ref(false);
const moreEl = ref<HTMLElement | null>(null);
function onDocClick(e: MouseEvent) {
  if (moreOpen.value && moreEl.value && !moreEl.value.contains(e.target as Node)) moreOpen.value = false;
}
onMounted(() => document.addEventListener("click", onDocClick));
onUnmounted(() => document.removeEventListener("click", onDocClick));
watch(() => route.fullPath, () => { moreOpen.value = false; });

/* Jobs: a quiet word when idle, the running job and its clock when not. */
const jf = useJobFeed();
const job = computed(() => { void jf.now; void jf.jobs; return headline(jf.jobs, boxNow()); });

/* Load: CPU as a share of what the container may use, memory against its
 * ceiling when there is one. Warm past 70%, failed-red past 90%. */
const load = computed(() => {
  if (!jf.loaded) return null;
  const c = jf.cpu, m = jf.memory;
  const used = m.cgroup_current ?? m.rss;
  const memPct = used != null && m.cgroup_max ? (used / m.cgroup_max) * 100 : null;
  const tone = (p: number | null) => (p == null ? "" : p >= 90 ? "bad" : p >= 70 ? "warm" : "");
  const cores = c.cores ? ` of ${+c.cores.toFixed(2)} core${c.cores === 1 ? "" : "s"}` : "";
  return {
    cpu: c.percent == null ? "—" : `${Math.round(c.percent)}%`,
    cpuTone: tone(c.percent),
    mem: memPct != null ? `${Math.round(memPct)}%` : bytes(used),
    memTone: tone(memPct),
    title: [
      `CPU ${c.percent == null ? "not measured yet" : c.percent + "%"}${cores}`
        + (c.container ? " (container)" : " (this process)"),
      `Memory ${bytes(used)}${m.cgroup_max ? " of " + bytes(m.cgroup_max) : ""}`
        + (m.cgroup_current != null ? " (container)" : " (this process)"),
      m.cgroup_peak != null ? `Peak ${bytes(m.cgroup_peak)}` : "",
      "Open Jobs",
    ].filter(Boolean).join("\n"),
  };
});

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
watch(() => route.fullPath, () => { if (open.value) { opener = null; open.value = false; } });

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape" && moreOpen.value) { moreOpen.value = false; e.preventDefault(); return; }
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
  forgetNames();
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
      <div class="bframe-more" ref="moreEl">
        <button class="bframe-btn" :class="{ on: moreHere || moreOpen }" @click="moreOpen = !moreOpen"
                aria-haspopup="menu" :aria-expanded="moreOpen">
          {{ moreHere?.name || "More" }} <Ico name="down" :size="12" />
        </button>
        <div class="bframe-menu" v-if="moreOpen" role="menu">
          <RouterLink v-for="i in MORE" :key="i.to" :to="i.to" role="menuitem"
                      :class="{ on: i.to === route.path }">
            <b>{{ i.name }}</b><em>{{ i.of }}</em>
          </RouterLink>
        </div>
      </div>
      <button class="bframe-btn bframe-places" @click="setOpen(true)"
              aria-haspopup="dialog" :aria-expanded="open" title="All places (g)">
        <Ico name="list" :size="15" /> <span class="lbl">{{ ALL.find((i) => here(i.to))?.name || "Places" }}</span>
      </button>

      <div class="bframe-grow" />

      <RouterLink class="bframe-btn bframe-jobs" :class="job?.tone" to="/settings?tab=jobs"
                  :title="job ? job.text + ' — open Jobs' : 'Nothing running in the background — open Jobs'"
                  role="status">
        <span class="led" aria-hidden="true" /><span class="lbl">{{ job?.text || "Jobs" }}</span>
      </RouterLink>

      <RouterLink v-if="load" class="bframe-btn bframe-load" to="/settings?tab=jobs" :title="load.title">
        <span :class="load.cpuTone"><em>CPU</em> {{ load.cpu }}</span>
        <span :class="load.memTone"><em>MEM</em> {{ load.mem }}</span>
      </RouterLink>

      <button class="bframe-btn" @click="pal?.show()" :aria-keyshortcuts="mod === '⌘K' ? 'Meta+K' : 'Control+K'">
        <Ico name="find" :size="15" /> <span class="lbl">Search</span> <kbd>{{ mod }}</kbd>
      </button>
      <div class="bframe-state" :class="state.cls" role="status"
           :title="state.cls === 'bad' ? 'The live feed is down; it reconnects by itself.' : undefined">
        <span class="led" aria-hidden="true" /><span class="lbl"><span>{{ state.label }}</span><span class="lbl-w" aria-hidden="true">not answering</span></span>
      </div>
      <div class="bframe-sep" />
      <button class="bframe-btn" @click="signOut">Sign out</button>
    </header>

    <div class="bsheet" v-if="open" @click.self="setOpen(false)">
      <nav class="bsheet-in" ref="sheet" role="dialog" aria-modal="true" aria-label="All places">
        <template v-for="g in PLACES" :key="g.group">
          <h4 class="b-cap">{{ g.group }}</h4>
          <RouterLink v-for="i in g.items" :key="i.to" :to="i.to" :class="{ on: here(i.to), sub: i.sub }"
                      :aria-current="here(i.to) ? 'page' : undefined">
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
