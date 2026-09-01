<script setup lang="ts">
/* Resolver — is it healthy, and where do answers come from.
 *
 * Two decisions worth stating.
 *
 * First, upstream latency is shown as one percentile strip *per upstream*, stacked
 * on a shared axis. Small multiples on a common scale are the correct comparison:
 * one chart with several overlaid distributions is unreadable, and a table of
 * averages hides the thing you are looking for — an upstream whose p50 is fine and
 * whose p99 is four seconds. That shape is what a failing resolver looks like
 * before it fails, and only a distribution shows it.
 *
 * Second, the cache is described in terms of what it saved rather than as a hit
 * rate. "38,402 queries answered without leaving the network" is the benefit; "84%
 * hit rate" is the same fact with the units removed.
 */
import { computed, onMounted, ref } from "vue";
import { api } from "../lib/api";
import { kindOf } from "../lib/outcome";
import type { Row } from "../lib/qlang";
import { store } from "../lib/store";
import Ico from "../ui/Ico.vue";
import Percentiles from "../ui/Percentiles.vue";

const nf = new Intl.NumberFormat();
const sys = ref<any>(null);
const rows = ref<Row[]>([]);
const loading = ref(true);
const err = ref("");
const busy = ref("");

/* Fetched rather than taken from the live socket: a view that only works while
 * the WebSocket happens to be connected is a view that shows "—" exactly when
 * something is wrong, which is when it is most needed. */
const stats = ref<any>(null);
const sampled = ref(0);
const windowTotal = ref(0);

async function load() {
  loading.value = true; err.value = "";
  try {
    const until = Date.now() * 1000;
    const [s, st, q] = await Promise.all([
      api.get("/system"),
      api.get("/stats").catch(() => null),
      api.get("/querylog" + api.qs({ since: until - 6 * 3600e6, until, limit: 1000 })),
    ]);
    sys.value = s;
    stats.value = st ?? store.state.stats;
    rows.value = q.rows || [];
    sampled.value = rows.value.length;
    windowTotal.value = q.total ?? rows.value.length;
  } catch (e: any) {
    err.value = e?.message || "the resolver could not be read";
  } finally { loading.value = false; }
}
onMounted(load);

function pct(sorted: number[], q: number) {
  if (!sorted.length) return 0;
  return Math.round(sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))] / 100) / 10;
}

/** One distribution per upstream, from the rows that actually travelled. */
const perUpstream = computed(() => {
  const m = new Map<string, number[]>();
  for (const r of rows.value) {
    if (!r.upstream || !r.elapsed_us) continue;
    const a = m.get(r.upstream);
    if (a) a.push(r.elapsed_us); else m.set(r.upstream, [r.elapsed_us]);
  }
  return [...m.entries()].map(([name, lat]) => {
    lat.sort((a, b) => a - b);
    return {
      name, n: lat.length,
      p50: pct(lat, 0.5), p95: pct(lat, 0.95), p99: pct(lat, 0.99),
    };
  }).sort((a, b) => b.n - a.n);
});

/* Configured upstreams that answered nothing in the window: either a fallback
 * that was never needed, or one that is not working. The view states the
 * ambiguity rather than picking one. */
const silent = computed(() => {
  const configured: string[] = sys.value?.upstream || [];
  const seen = new Set(perUpstream.value.map((u) => u.name));
  return configured.filter((c) => ![...seen].some((s) => s.includes(c.replace(/^\w+:\/\//, "").split("#")[0])));
});

const composition = computed(() => {
  const by: Record<string, number> = {};
  for (const r of rows.value) by[kindOf(r)] = (by[kindOf(r)] || 0) + 1;
  const total = rows.value.length || 1;
  const free = (by.cache || 0) + (by.local || 0);
  return { total, free, freePct: Math.round((free / total) * 100), by };
});

const transports = computed(() => {
  const list: string[] = sys.value?.upstream || [];
  return list.map((u) => {
    const scheme = /^(\w+):\/\//.exec(u)?.[1] || "udp";
    const encrypted = ["tls", "https", "quic"].includes(scheme);
    return { spec: u, scheme, encrypted };
  });
});

async function act(what: "flush" | "refresh") {
  busy.value = what;
  try {
    if (what === "flush") {
      const r = await api.post("/cache/flush");
      store.toast("Cache flushed", `${nf.format(r.flushed ?? 0)} entries dropped`);
    } else {
      await api.post("/gravity/refresh");
      store.toast("Refresh started", "the lists are being downloaded and recompiled");
    }
  } catch (e: any) {
    store.toast("Failed", e?.message || "", true);
  } finally { busy.value = ""; }
}

const uptime = computed(() => {
  const s = sys.value?.uptime ?? 0;
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return (d ? `${d}d ` : "") + (h ? `${h}h ` : "") + `${m}m`;
});
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Resolver</h2>
      <div class="acts">
        <button class="btn" @click="act('refresh')" :disabled="busy === 'refresh'">
          <Ico name="list" /> refresh lists
        </button>
        <button class="btn risk" @click="act('flush')" :disabled="busy === 'flush'">
          flush cache
        </button>
      </div>
    </header>

    <div class="vw-body">
      <div class="sec">
        <dl class="kvs">
          <dt>Version</dt><dd>{{ sys?.version || "—" }}</dd>
          <dt>Running for</dt><dd class="ui">{{ uptime }}</dd>
          <dt>Mode</dt>
          <dd class="ui">
            {{ sys?.mode === "recursive" ? "recursive — this machine walks the tree itself"
              : "forwarding — questions go to the upstreams below" }}
          </dd>
          <dt>Blocklist</dt>
          <dd class="ui" v-if="stats">{{ nf.format(stats.blocklist_size) }} names</dd>
          <dd class="ui" v-else>—</dd>
          <dt>Cache</dt>
          <dd class="ui" v-if="stats">{{ nf.format(stats.cache_size) }} entries held</dd>
          <dd class="ui" v-else>—</dd>
        </dl>
      </div>

      <!-- the cache, described as what it saved -->
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Where answers came from</h5>
          <span class="b-cap" v-if="windowTotal > sampled">
            last {{ nf.format(sampled) }} of {{ nf.format(windowTotal) }}
          </span>
        </div>
        <div class="ev-big">
          <b>{{ nf.format(composition.free) }}</b>
          <span>of {{ nf.format(composition.total) }} answered without leaving this network</span>
        </div>
        <div class="mtr" style="margin-top:12px">
          <i :style="{ width: (composition.freePct) + '%', background: 'var(--o-cache)' }" />
          <i :style="{ width: ((composition.by.upstream || 0) / composition.total * 100) + '%', background: 'var(--o-upstream)' }" />
          <i :style="{ width: ((composition.by.blocked || 0) / composition.total * 100) + '%', background: 'var(--o-blocked)' }" />
          <i :style="{ width: ((composition.by.failed || 0) / composition.total * 100) + '%', background: 'var(--o-failed)' }" />
        </div>
        <div class="mtr-l">
          <span class="oc"><i style="background:var(--o-cache)" /><span class="b-cap">cached {{ composition.freePct }}%</span></span>
          <span class="oc"><i style="background:var(--o-upstream)" /><span class="b-cap">forwarded {{ nf.format(composition.by.upstream || 0) }}</span></span>
          <span class="oc"><i style="background:var(--o-blocked)" /><span class="b-cap">blocked {{ nf.format(composition.by.blocked || 0) }}</span></span>
          <span class="oc" v-if="composition.by.failed"><i style="background:var(--o-failed)" /><span class="b-cap">failed {{ nf.format(composition.by.failed) }}</span></span>
        </div>
      </div>

      <!-- small multiples on a shared axis -->
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Time to answer</h5>
          <span class="b-cap">log scale</span>
        </div>
        <div v-for="u in perUpstream" :key="u.name" style="margin-bottom:16px">
          <div style="display:flex;gap:12px;align-items:baseline">
            <span class="mono" style="color:var(--b-ink)">{{ u.name }}</span>
            <span class="b-cap">{{ nf.format(u.n) }} queries</span>
            <span class="b-cap" style="margin-left:auto"
                  :style="u.p99 > 1000 ? { color: 'var(--o-failed)' } : {}">
              p99 {{ u.p99 }} ms
            </span>
          </div>
          <Percentiles :p50="u.p50" :p95="u.p95" :p99="u.p99" />
        </div>
        <p class="b-void-state" v-if="!perUpstream.length && !loading">
          Nothing was forwarded in the last six hours — every answer came from cache,
          local authority, or was blocked.
        </p>
        <p class="sec-note" v-if="silent.length">
          Configured but silent in this window:
          <code>{{ silent.join(", ") }}</code>. That is either a fallback that was
          never needed or one that is not working; this view cannot tell which, and
          the failed count above is where the difference would show.
        </p>
      </div>

      <!-- what the resolver discloses upstream -->
      <div class="sec">
        <div class="sec-h"><h5 class="b-cap">Upstreams and what they can see</h5></div>
        <table class="tb">
          <thead>
            <tr><th>Upstream</th><th style="width:120px">Transport</th><th>What it learns</th></tr>
          </thead>
          <tbody>
            <tr v-for="t in transports" :key="t.spec">
              <td class="id">{{ t.spec }}</td>
              <td>
                <span class="oc">
                  <i :style="`background:var(--o-${t.encrypted ? 'upstream' : 'failed'})`" />
                  {{ t.scheme }}
                </span>
              </td>
              <td>
                <template v-if="t.encrypted">
                  Every name this resolver forwards, but the path is authenticated
                  and encrypted, so the network in between learns nothing.
                </template>
                <template v-else>
                  Every name this resolver forwards — in clear text, so any network
                  in between learns it too, and can change the answer.
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="b-warn" v-if="err">{{ err }}</p>
    </div>
  </div>
</template>
