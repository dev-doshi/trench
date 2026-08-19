<script setup lang="ts">
/* The entity panel — one name or one device, from anywhere.
 *
 * Opened with store.inspect("domain"|"client", value). It exists so that a name
 * mentioned in a table is never a dead end, without forcing a navigation that
 * loses the screen you were reading. That is also why it is the only floating
 * surface in the product: it is genuinely temporary, and the thing underneath is
 * still the thing you care about.
 *
 * It shows what is in the live buffer and what the log remembers, then hands off:
 * every action here leads somewhere that can do more.
 */
import { computed, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api } from "../lib/api";
import { align } from "../lib/dnsname";
import { KINDS, kindOf, meta } from "../lib/outcome";
import type { Row } from "../lib/qlang";
import { store } from "../lib/store";
import { copyText } from "../lib/util";
import Ico from "./Ico.vue";
import Spine from "./Spine.vue";

const router = useRouter();
const s = store.state;
const nf = new Intl.NumberFormat();
const hist = ref<{ rows: Row[]; total: number }>({ rows: [], total: 0 });
const loading = ref(false);

const ent = computed(() => s.inspecting);
const isDomain = computed(() => ent.value?.kind === "domain");

watch(ent, async (e) => {
  hist.value = { rows: [], total: 0 };
  if (!e) return;
  loading.value = true;
  try {
    const qs = e.kind === "domain" ? { qname: e.value } : { client: e.value };
    hist.value = await api.get("/querylog" + api.qs({ ...qs, limit: 40 }));
  } catch { /* the log may be off; the live section still renders */ }
  finally { loading.value = false; }
});

/** The live buffer, sliced to this entity. */
const live = computed(() => {
  if (!ent.value) return [] as Row[];
  const { kind, value } = ent.value;
  return s.live
    .filter((x) => (kind === "domain" ? x.domain === value : x.client === value))
    .map((e) => ({
      ts: e.ts > 1e12 ? e.ts : Math.round(e.ts * 1e6),
      client_ip: e.client, qname: e.domain, qtype: e.type, action: e.action,
      rcode: e.rcode, upstream: e.upstream, elapsed_us: e.elapsed_us, reason: e.reason,
    } as Row));
});

/** Everything we hold about it, live plus recorded, deduplicated by timestamp. */
const all = computed(() => {
  const seen = new Set<number>();
  const out: Row[] = [];
  for (const r of [...live.value, ...hist.value.rows]) {
    if (seen.has(r.ts)) continue;
    seen.add(r.ts);
    out.push(r);
  }
  return out.sort((a, b) => b.ts - a.ts);
});

const summary = computed(() => {
  const by: Record<string, number> = {};
  const others = new Set<string>();
  let lat = 0, latN = 0;
  for (const r of all.value) {
    by[kindOf(r)] = (by[kindOf(r)] || 0) + 1;
    others.add(isDomain.value ? r.client_ip : r.qname.toLowerCase());
    if (r.elapsed_us) { lat += r.elapsed_us; latN++; }
  }
  return {
    total: all.value.length, by, others: others.size,
    avg: latN ? Math.round(lat / latN) : 0,
    kinds: KINDS.filter((k) => by[k]).map((k) => ({ kind: k, label: meta(k).label, n: by[k] })),
  };
});

const spine = computed(() => ({
  cache: summary.value.by.cache || 0, upstream: summary.value.by.upstream || 0,
  local: summary.value.by.local || 0, blocked: summary.value.by.blocked || 0,
  failed: summary.value.by.failed || 0, unknown: summary.value.by.unknown || 0,
}));

async function rule(action: "deny" | "allow") {
  if (!ent.value) return;
  try {
    await api.post("/rules", { domain: ent.value.value, action });
    store.toast(action === "deny" ? "Now refused" : "Now allowed",
                `${ent.value.value} and everything under it`);
  } catch (e: any) { store.toast("Unchanged", e?.message || "", true); }
}

function go(where: "browse" | "log") {
  if (!ent.value) return;
  const q = isDomain.value ? `name=${ent.value.value}` : `client=${ent.value.value}`;
  router.push({ path: where === "browse" ? "/" : "/log", query: { q } });
  store.closeInspector();
}

const stamp = (us: number) => new Date(us / 1000).toLocaleString();
const ms = (us?: number) => (!us ? "—" : us >= 1000 ? `${(us / 1000).toFixed(1)} ms` : `${us} µs`);
</script>

<template>
  <template v-if="ent">
    <div class="insp-bg" @mousedown="store.closeInspector()" />
    <aside class="insp" @keydown.esc="store.closeInspector()">
      <div class="ihead">
        <div>
          <span class="b-cap">{{ isDomain ? "Name" : "Device" }}</span>
          <span class="t" style="display:block" v-if="isDomain">
            <span style="color:var(--b-ink-4)">{{ align(ent.value).sub }}{{ align(ent.value).sub ? "." : "" }}</span>{{ align(ent.value).reg }}
          </span>
          <span class="t" style="display:block" v-else>{{ ent.value }}</span>
        </div>
        <span class="x">
          <button class="btn" @click="store.closeInspector()"><Ico name="shut" :size="14" /></button>
        </span>
      </div>

      <div class="ibody">
        <div class="isec">
          <span class="t">What is known</span>
          <div class="ev-big">
            <b>{{ nf.format(summary.total) }}</b>
            <span>queries held here</span>
            <span class="b-cap" style="margin-left:auto" v-if="hist.total">
              {{ nf.format(hist.total) }} in the log
            </span>
          </div>
          <div style="margin-top:10px" v-if="summary.total">
            <Spine :by="spine" :total="summary.total" :max="summary.total" />
          </div>
          <div class="mtr-l" v-if="summary.kinds.length">
            <span class="oc" v-for="k in summary.kinds" :key="k.kind" :class="k.kind">
              <i :style="k.kind === 'unknown' ? '' : `background:var(--o-${k.kind})`" />
              <span class="b-cap">{{ k.label }} {{ nf.format(k.n) }}</span>
            </span>
          </div>
          <dl class="kvs" style="margin-top:12px">
            <dt>{{ isDomain ? "Asked by" : "Distinct names" }}</dt>
            <dd class="ui">{{ nf.format(summary.others) }}</dd>
            <dt>Average time</dt><dd class="ui">{{ ms(summary.avg) }}</dd>
          </dl>
          <p class="b-void-state" style="padding:12px 0" v-if="!summary.total && !loading">
            Nothing about this is held right now. Either it has not been asked for
            recently, or the query log is off — Privacy says which.
          </p>
        </div>

        <div class="isec">
          <span class="t">Do something with it</span>
          <div class="row-acts">
            <button class="btn" @click="go('browse')"><Ico name="levels" /> in Browse</button>
            <button class="btn" @click="go('log')"><Ico name="list" /> in the Log</button>
            <button class="btn" @click="copyText(ent.value); store.toast('Copied', ent.value)">
              <Ico name="copy" /> copy
            </button>
          </div>
          <div class="row-acts" style="margin-top:8px" v-if="isDomain">
            <button class="btn risk" @click="rule('deny')"><Ico name="held" /> block it</button>
            <button class="btn" @click="rule('allow')"><Ico name="kept" /> allow it</button>
          </div>
          <p class="sec-note" style="margin:8px 0 0" v-if="isDomain">
            Both apply to this name and everything under it, and take effect at once.
            Policy shows them afterwards with what they went on to decide.
          </p>
        </div>

        <div class="isec">
          <span class="t">Most recent</span>
          <table class="tb" v-if="all.length">
            <thead>
              <tr>
                <th style="width:150px">When</th>
                <th>{{ isDomain ? "Device" : "Name" }}</th>
                <th style="width:96px">Outcome</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(r, i) in all.slice(0, 14)" :key="r.ts + '-' + i">
                <td style="color:var(--b-ink-3)">{{ stamp(r.ts) }}</td>
                <td class="id">{{ isDomain ? (r.client_id || r.client_ip) : r.qname }}</td>
                <td>
                  <span class="oc">
                    <i :style="kindOf(r) === 'unknown' ? '' : `background:var(--o-${kindOf(r)})`" />
                    {{ meta(kindOf(r)).label }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
          <p class="b-void-state" style="padding:10px 0" v-else-if="loading">Reading…</p>
        </div>
      </div>
    </aside>
  </template>
</template>
