<script setup lang="ts">
/* Jobs — what the resolver is doing when nobody asked it anything.
 *
 * A blocklist build is minutes of the heaviest work this process does, on a box
 * whose memory ceiling the whole design is arranged around, and until this page
 * existed its only trace was the container log. A refresh that kept the old
 * rules because one list was down looked exactly like one that had worked.
 *
 * Three questions, in the order they are asked: are the lists what I configured
 * (and how much memory did it take to get there), what ran and how did it go,
 * and which list is the one that failed. Every job with something to run can be
 * run from here; reloading re-reads the config file, the way SIGHUP does.
 */
import { computed, ref } from "vue";
import { api } from "../lib/api";
import { boxNow, feed, refresh, soon, useJobFeed } from "../lib/jobfeed";
import {
  ago, bytes, duration, labelOf, order, purposeOf, resultWord, sourceLabel, toneOf, until,
  type Job,
} from "../lib/jobs";
import { store } from "../lib/store";

withDefaults(defineProps<{ embedded?: boolean }>(), { embedded: false });

useJobFeed();
const nf = new Intl.NumberFormat();
const role = computed(() => store.state.user?.role || "viewer");
const canRun = computed(() => role.value === "editor" || role.value === "admin");
const isAdmin = computed(() => role.value === "admin");
const starting = ref(new Set<string>());

const jobs = computed(() => order(feed.jobs));
const now = computed(() => { void feed.now; return boxNow(); });
const lists = computed(() => feed.jobs.find((j) => j.name === "gravity-refresh"));
const reload = computed(() => feed.jobs.find((j) => j.name === "reload"));

const failedSources = computed(() => feed.sources.filter((s) => s.status !== "ok"));
const sources = computed(() => [...feed.sources].sort((a, b) =>
  Number(a.status === "ok") - Number(b.status === "ok") || b.rule_count - a.rule_count));

/** The container's ceiling is what gets a build killed, so memory is stated
 *  against it when the kernel says what it is. */
const mem = computed(() => {
  const m = feed.memory;
  const used = m.cgroup_current ?? m.rss;
  return { used, max: m.cgroup_max, peak: m.cgroup_peak,
           pct: used && m.cgroup_max ? Math.round((used / m.cgroup_max) * 100) : null };
});

async function run(j: Job | undefined, name = j?.name || "") {
  if (!name || starting.value.has(name)) return;
  starting.value = new Set(starting.value).add(name);
  try {
    if (name === "reload") await api.post("/reload");
    else await api.post(`/jobs/${name}/run`);
    store.toast(`${labelOf(name)} started`,
                name === "gravity-refresh" ? "the current lists keep answering until the new ones are ready" : "");
    soon();
  } catch (e: any) {
    store.toast(`${labelOf(name)} not started`, e?.message || "", true);
  } finally {
    const s = new Set(starting.value); s.delete(name); starting.value = s;
  }
}

const when = (t: number | null | undefined) => (t ? ago(t, now.value) : "never");
</script>

<template>
  <div :class="embedded ? 'jb-embed' : 'vw'">
    <header class="vw-head" v-if="!embedded">
      <h2>Jobs</h2>
      <div class="acts"><button class="btn" @click="refresh">reload</button></div>
    </header>

    <div :class="embedded ? '' : 'vw-body'">
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Blocklists</h5>
          <div class="acts">
            <button class="btn" v-if="canRun" :disabled="lists?.running || starting.has('gravity-refresh')"
                    @click="run(lists, 'gravity-refresh')"
                    title="Fetch every list and rebuild. What is running keeps answering until the new table is ready.">
              {{ lists?.running ? "refreshing…" : "refresh lists now" }}
            </button>
            <button class="btn" v-if="isAdmin" :disabled="reload?.running || starting.has('reload')"
                    @click="run(reload, 'reload')"
                    title="Re-read the config file from disk, apply it, then refresh the lists — what SIGHUP does">
              {{ reload?.running ? "reloading…" : "reload config & lists" }}
            </button>
          </div>
        </div>

        <dl class="jb-facts" v-if="feed.loaded">
          <div>
            <dt>Serving</dt>
            <dd>
              <b>{{ feed.table.domains != null ? nf.format(feed.table.domains) : "—" }}</b> domains
              <span class="sub" v-if="feed.table.built_at">built {{ when(feed.table.built_at) }}</span>
            </dd>
          </div>
          <div>
            <dt>Matches the config</dt>
            <dd>
              <template v-if="feed.table.matches_config">yes</template>
              <span class="b-warn-i" v-else-if="feed.table.built_at != null || feed.table.domains">
                no — {{ feed.table.complete === false ? "the last build was not complete" : "the lists changed since it was built" }};
                {{ lists?.running ? "rebuilding now" : "refresh to apply" }}
              </span>
              <template v-else>not built yet</template>
            </dd>
          </div>
          <div>
            <dt>Last refresh</dt>
            <dd>
              <span :class="'jb-t ' + (lists ? toneOf(lists) : '')">{{ lists ? resultWord(lists) : "—" }}</span>
              <span class="sub" v-if="lists?.finished && !lists.running">
                {{ when(lists.finished) }} · took {{ duration(lists.duration) }}
                <template v-if="lists.peak_rss"> · peak {{ bytes(lists.peak_rss) }}</template>
              </span>
              <span class="sub" v-else-if="lists?.running && lists.started">for {{ duration(now - lists.started) }}</span>
            </dd>
          </div>
          <div>
            <dt>Memory</dt>
            <dd>
              <b>{{ bytes(mem.used) }}</b>
              <template v-if="mem.max"> of {{ bytes(mem.max) }} <span class="sub">({{ mem.pct }}%)</span></template>
              <span class="sub" v-if="mem.peak">container peak since start {{ bytes(mem.peak) }}</span>
            </dd>
          </div>
        </dl>
        <p class="jb-detail" v-if="lists?.detail">{{ lists.detail }}</p>
      </div>

      <div class="sec">
        <div class="sec-h"><h5 class="b-cap">Jobs</h5><span class="b-cap">{{ jobs.length }}</span></div>
        <table class="tb" v-if="jobs.length">
          <thead>
            <tr>
              <th>Job</th>
              <th style="width:34%">Last run</th>
              <th style="width:120px">Next</th>
              <th class="r" style="width:80px">Runs</th>
              <th style="width:96px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="j in jobs" :key="j.name">
              <td>
                {{ labelOf(j.name) }}
                <span class="sub">{{ purposeOf(j.name) || j.name }}</span>
              </td>
              <td>
                <span :class="'jb-t ' + toneOf(j)">{{ resultWord(j) }}</span>
                <template v-if="j.running && j.started"> · {{ duration(now - j.started) }}</template>
                <template v-else-if="j.finished"> · {{ when(j.finished) }}<template v-if="j.duration && j.duration >= 1">, {{ duration(j.duration) }}</template></template>
                <span class="sub" v-if="j.detail" :title="j.detail">{{ j.detail }}</span>
              </td>
              <td>
                {{ j.interval ? until(j.next_at, now) : "by hand" }}
                <span class="sub" v-if="j.interval">every {{ duration(j.interval) }}</span>
              </td>
              <td class="r">
                {{ nf.format(j.runs) }}
                <span class="sub" v-if="j.failures">{{ j.failures }} failed</span>
              </td>
              <td class="r">
                <button class="btn" v-if="j.runnable && (j.name === 'reload' ? isAdmin : canRun)"
                        :disabled="j.running || starting.has(j.name)" @click="run(j)">
                  {{ j.running ? "running" : "run now" }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="b-void-state" v-else-if="feed.loaded">Nothing is scheduled.</p>
      </div>

      <div class="sec" v-if="sources.length">
        <div class="sec-h">
          <h5 class="b-cap">Sources</h5>
          <span class="b-cap">{{ sources.length }}<template v-if="failedSources.length"> · {{ failedSources.length }} failing</template></span>
        </div>
        <table class="tb">
          <thead>
            <tr><th>List</th><th class="r" style="width:110px">Rules</th><th style="width:140px">Fetched</th><th style="width:38%">Status</th></tr>
          </thead>
          <tbody>
            <tr v-for="s in sources" :key="s.url">
              <td class="id" :title="s.url">{{ sourceLabel(s.url) }}</td>
              <td class="r">{{ nf.format(s.rule_count) }}</td>
              <td>{{ when(s.last_update) }}</td>
              <td>
                <span :class="'jb-t ' + (s.status === 'ok' ? 'ok' : 'bad')">{{ s.status === "ok" ? "ok" : "failed" }}</span>
                <span class="sub" v-if="s.error" :title="s.error">{{ s.error }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="b-void-state" v-if="!feed.loaded && !feed.error">Reading…</p>
      <p class="b-warn" v-if="feed.error">{{ feed.error }}</p>
    </div>
  </div>
</template>
