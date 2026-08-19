<script setup lang="ts">
/* Devices — who is on the network, and what each one is like.
 *
 * A grid of device cards is the standard answer and it is useless: it shows
 * twelve identical tiles and answers none of the questions an operator has.
 * The real questions are comparative — which device is behaving unlike itself,
 * which ones are the same kind of thing, which are not really identified at all.
 *
 * So this is one table, and the columns are chosen to make comparison possible:
 *   · a device's *vocabulary* (how many distinct registrable domains it asks for)
 *     separates an appliance from a browser more reliably than any label. Four
 *     domains is a lightbulb; four hundred is somebody's laptop
 *   · its blocked share, as a spine, so a device that is mostly being refused
 *     stands out without reading a number
 *   · how it was identified, because an address from a lease that expired weeks
 *     ago is not an identity, and a view that shows a name without its basis
 *     invites you to trust it
 *   · unidentified devices are not hidden at the bottom; they are a section with
 *     the evidence needed to name them, because that is a queue of work
 */
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { api } from "../lib/api";
import { registrable } from "../lib/dnsname";
import { kindOf } from "../lib/outcome";
import type { Row } from "../lib/qlang";
import Spine from "../ui/Spine.vue";

const router = useRouter();
const nf = new Intl.NumberFormat();

const managed = ref<any[]>([]);
const groups = ref<any[]>([]);
const rows = ref<Row[]>([]);
const loading = ref(true);
const err = ref("");

async function load() {
  loading.value = true; err.value = "";
  try {
    const until = Date.now() * 1000;
    const [c, g, q] = await Promise.all([
      api.get("/clients/manage").catch(() => ({ clients: [] })),
      api.get("/groups").catch(() => ({ groups: [] })),
      api.get("/querylog" + api.qs({ since: until - 24 * 3600e6, until, limit: 1000 })),
    ]);
    managed.value = c.clients || [];
    groups.value = g.groups || [];
    rows.value = q.rows || [];
  } catch (e: any) {
    err.value = e?.message || "the devices could not be read";
  } finally { loading.value = false; }
}
onMounted(load);

/** Everything the log knows about each address in the window. */
const seen = computed(() => {
  const m = new Map<string, {
    ip: string; total: number; blocked: number; failed: number; cache: number;
    upstream: number; local: number; unknown: number;
    vocab: Set<string>; names: Set<string>; last: number;
  }>();
  for (const r of rows.value) {
    const ip = r.client_ip;
    if (!ip) continue;
    let e = m.get(ip);
    if (!e) {
      e = { ip, total: 0, blocked: 0, failed: 0, cache: 0, upstream: 0, local: 0,
            unknown: 0, vocab: new Set(), names: new Set(), last: 0 };
      m.set(ip, e);
    }
    e.total++;
    e[kindOf(r)]++;
    e.vocab.add(registrable(r.qname));
    e.names.add(r.qname.toLowerCase());
    if (r.ts > e.last) e.last = r.ts;
  }
  return m;
});

const byIdent = computed(() => {
  const m = new Map<string, any>();
  for (const c of managed.value) {
    const k = String(c.ident ?? c.ip ?? "").toLowerCase();
    if (k) m.set(k, c);
  }
  return m;
});

const table = computed(() => {
  const out = [...seen.value.values()].map((e) => {
    const c = byIdent.value.get(e.ip.toLowerCase());
    return {
      ...e,
      name: c?.name || "",
      identBy: c?.ident_type || "",
      group: c?.group_name || c?.group || "",
      vocabN: e.vocab.size,
      blockedPct: Math.round((e.blocked / Math.max(1, e.total)) * 100),
      by: { cache: e.cache, upstream: e.upstream, local: e.local,
            blocked: e.blocked, failed: e.failed, unknown: e.unknown },
    };
  });
  return out.sort((a, b) => b.total - a.total);
});

const max = computed(() => Math.max(1, ...table.value.map((t) => t.total)));
const named = computed(() => table.value.filter((t) => t.name));
const unnamed = computed(() => table.value.filter((t) => !t.name));

/**
 * What a device's vocabulary suggests it is — a guess, never stated as fact.
 *
 * Kept to two or three words. The first version of this was a full sentence and
 * it wrapped to five lines inside a numeric column, which tripled every row's
 * height and destroyed the scannability the table exists for. The evidence for
 * the guess is the domain list beside it, which is more use than a longer label.
 */
function character(vocabN: number, total: number): string {
  if (!total) return "";
  if (vocabN <= 3) return "appliance";
  if (vocabN <= 12) return "a few services";
  if (vocabN <= 60) return "several apps";
  return "browser-like";
}

const ago = (us: number) => {
  const d = (Date.now() * 1000 - us) / 1e6;
  if (d < 60) return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
};

function browse(ip: string) {
  router.push({ path: "/", query: { p: "device,domain,name", s: ip } });
}
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Devices</h2>
      <div class="acts">
        <button class="btn" @click="load">reload</button>
      </div>
    </header>

    <div class="vw-body">
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Identified</h5>
          <span class="b-cap">{{ named.length }} of {{ table.length }} seen</span>
        </div>
        <table class="tb" v-if="named.length">
          <thead>
            <tr>
              <th>Device</th>
              <th class="r" style="width:80px">Queries</th>
              <th class="r" style="width:74px">Domains</th>
              <th style="width:124px">Looks like</th>
              <th>What it asks for</th>
              <th style="width:22%">Outcomes</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in named" :key="d.ip" class="click" @click="browse(d.ip)">
              <td class="id">
                {{ d.name }}
                <span class="sub">
                  {{ d.ip }}<template v-if="d.group"> · {{ d.group }}</template>
                  · {{ d.identBy || "not identified" }} · {{ ago(d.last) }}
                </span>
              </td>
              <td class="r">{{ nf.format(d.total) }}</td>
              <td class="r">{{ nf.format(d.vocabN) }}</td>
              <td>{{ character(d.vocabN, d.total) }}</td>
              <td class="id" style="color:var(--b-ink-2)">
                {{ [...d.vocab].slice(0, 2).join("  ") }}<template v-if="d.vocabN > 2"> …</template>
              </td>
              <td>
                <Spine :by="d.by" :total="d.total" :max="max" />
                <span class="sub">{{ d.blockedPct }}% blocked</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="b-void-state" v-else-if="!loading">
          No device has a name yet.
        </p>
      </div>

      <!-- a queue of work, not a footnote -->
      <div class="sec" v-if="unnamed.length">
        <div class="sec-h">
          <h5 class="b-cap">Not identified</h5>
          <span class="b-cap">{{ unnamed.length }}</span>
        </div>
        <table class="tb">
          <thead>
            <tr>
              <th>Address</th>
              <th class="r" style="width:88px">Queries</th>
              <th class="r" style="width:96px">Domains</th>
              <th>What it asks for</th>
              <th style="width:26%">Outcomes</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in unnamed" :key="d.ip" class="click" @click="browse(d.ip)">
              <td class="id">
                {{ d.ip }}
                <span class="sub">{{ character(d.vocabN, d.total) }} · {{ ago(d.last) }}</span>
              </td>
              <td class="r">{{ nf.format(d.total) }}</td>
              <td class="r">{{ nf.format(d.vocabN) }}</td>
              <td class="id" style="color:var(--b-ink-2)">
                {{ [...d.vocab].slice(0, 3).join("  ") }}<template v-if="d.vocabN > 3"> …</template>
              </td>
              <td>
                <Spine :by="d.by" :total="d.total" :max="max" />
                <span class="sub">{{ d.blockedPct }}% blocked</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="sec" v-if="groups.length">
        <div class="sec-h"><h5 class="b-cap">Groups</h5><span class="b-cap">{{ groups.length }}</span></div>
        <table class="tb">
          <thead><tr><th>Group</th><th style="width:40%">Tags</th></tr></thead>
          <tbody>
            <tr v-for="g in groups" :key="g.id ?? g.name">
              <td class="id">{{ g.name }}</td>
              <td>{{ g.ctags || g.tags || "—" }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="b-void-state" v-if="loading">Reading the last day…</p>
      <p class="b-warn" v-if="err">{{ err }}</p>
    </div>
  </div>
</template>
