<script setup lang="ts">
/* Breakage — blocks that look like something stopped working, and lists judged
 * by what they earn.
 *
 * The hard problem in DNS filtering is not blocking. It is knowing which of your
 * blocks broke something, because the symptom appears on a device that cannot
 * report it. The backend already detects the signature — a client retrying the
 * same refused name in a tight loop, recurring across many windows — so this view
 * is a triage queue, not a chart.
 *
 * Decisions:
 *   · each finding leads with the *evidence sentence*, not a score. "27 lookups
 *     from one device, 1.4s apart, recurring across 9 windows" is something an
 *     operator can judge; "score 8.4" is something they have to trust
 *   · the action is one click and it is narrow: allow this exact name. Nothing
 *     here offers "disable filtering", because the fix for one broken device is
 *     never to stop filtering the network
 *   · list weight is shown as what it earns, not as its size. A list with 400,000
 *     names that blocked nothing this week is dead weight and should say so; a
 *     threat feed that blocked nothing is doing its job and must not be judged
 *     the same way, which is why the backend marks protective lists separately
 */
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { api } from "../lib/api";
import { align } from "../lib/dnsname";
import { store } from "../lib/store";

const router = useRouter();
const nf = new Intl.NumberFormat();

const findings = ref<any[]>([]);
const high = ref(0);
const hours = ref(24);
const lists = ref<any>(null);
const reviews = ref<any[]>([]);
const loading = ref(true);
const err = ref("");
const allowed = ref<Set<string>>(new Set());

async function load() {
  loading.value = true; err.value = "";
  try {
    const [c, l, r] = await Promise.all([
      api.get("/collateral" + api.qs({ hours: hours.value })),
      api.get("/lists" + api.qs({ hours: hours.value })).catch(() => null),
      api.get("/list-reviews" + api.qs({ limit: 5 })).catch(() => ({ reviews: [] })),
    ]);
    findings.value = c.findings || [];
    high.value = c.high || 0;
    lists.value = l;
    reviews.value = r?.reviews || [];
  } catch (e: any) {
    err.value = e?.message || "the analysis could not be run";
  } finally { loading.value = false; }
}
onMounted(load);

/** The evidence, as a sentence an operator can judge. */
function evidence(f: any): string {
  const bits: string[] = [];
  bits.push(`${nf.format(f.hits)} lookup${f.hits === 1 ? "" : "s"}`);
  bits.push(`from ${f.client_count} device${f.client_count === 1 ? "" : "s"}`);
  if (f.retries) bits.push(`${nf.format(f.retries)} of them retries`);
  if (f.median_gap_s) bits.push(`typically ${f.median_gap_s}s apart`);
  if (f.buckets > 1) bits.push(`recurring across ${f.buckets} separate windows`);
  return bits.join(", ") + ".";
}

async function allowIt(f: any) {
  try {
    await api.post("/rules", { domain: f.domain, action: "allow" });
    allowed.value = new Set([...allowed.value, f.domain]);
    store.toast("Allowed", `${f.domain} — and everything under it`);
  } catch (e: any) {
    store.toast("Not allowed", e?.message || "", true);
  }
}

const latest = computed(() => reviews.value[0] || null);
const listRows = computed(() => (lists.value?.lists || []) as any[]);
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Breakage</h2>
      <div class="acts">
        <select class="sel" style="width:auto" v-model.number="hours" @change="load">
          <option :value="6">6 hours</option>
          <option :value="24">24 hours</option>
          <option :value="72">3 days</option>
        </select>
        <button class="btn" @click="load">re-run</button>
      </div>
    </header>

    <div class="vw-body">
      <p class="b-warn" v-if="high" style="margin:0 -20px">
        {{ high }} finding{{ high === 1 ? "" : "s" }} with a strong retry signature.
        Those are the ones most likely to be a real device stuck in a loop.
      </p>

      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Suspected breakage</h5>
          <span class="b-cap">{{ findings.length }} in {{ hours }}h</span>
        </div>

        <div v-for="f in findings" :key="f.domain"
             style="padding:13px 0;border-bottom:1px solid var(--b-edge-soft)">
          <div style="display:flex;gap:12px;align-items:baseline;flex-wrap:wrap">
            <span class="vd" :class="f.severity === 'high' ? 'warn' : 'calm'">
              {{ f.severity }}
            </span>
            <a class="mono" style="font-size:var(--b-read-s);color:var(--b-ink);cursor:pointer"
               @click="router.push({ path: '/', query: { q: `name=${f.domain}` } })">
              <span style="color:var(--b-ink-4)">{{ align(f.domain).sub }}{{ align(f.domain).sub ? "." : "" }}</span>{{ align(f.domain).reg }}
            </a>
            <span class="b-cap" style="margin-left:auto" v-if="allowed.has(f.domain)">allowed</span>
            <button class="btn-q" v-else @click="allowIt(f)">allow this name</button>
          </div>
          <p class="sec-note" style="margin:5px 0 0">{{ evidence(f) }}</p>
          <p class="sec-note" style="margin:3px 0 0" v-if="f.rule">
            Blocked by <code>{{ f.rule }}</code><template v-if="f.source"> from {{ f.source }}</template>.
          </p>
          <p class="sec-note" style="margin:3px 0 0;color:var(--b-ink-4)" v-if="f.clients?.length">
            {{ f.clients.slice(0, 4).join(", ") }}<template v-if="f.clients.length > 4">, and {{ f.clients.length - 4 }} more</template>
          </p>
        </div>

        <p class="b-void-state" v-if="!loading && !findings.length">
          Nothing in the last {{ hours }} hours looks like breakage.
        </p>
        <p class="b-void-state" v-if="loading">Replaying the last {{ hours }} hours…</p>
      </div>

      <!-- what the last blocklist update did -->
      <div class="sec" v-if="latest">
        <div class="sec-h">
          <h5 class="b-cap">Last list update</h5>
          <span class="b-cap">{{ new Date(latest.ts * 1000).toLocaleString() }}</span>
        </div>
        <p class="sec-note">
          The list went from {{ nf.format(latest.domains_before) }} to
          {{ nf.format(latest.domains_after) }} names.
          <b v-if="latest.high_risk">
            {{ latest.high_risk }} name{{ latest.high_risk === 1 ? "" : "s" }} that had been
            answered started being refused — that is where breakage comes from.
          </b>
          <template v-else>Nothing that was being answered started being refused.</template>
        </p>
      </div>

      <!-- lists judged by what they earn -->
      <div class="sec" v-if="listRows.length">
        <div class="sec-h">
          <h5 class="b-cap">List weight</h5>
          <span class="b-cap">
            {{ lists.total_domains ? nf.format(lists.total_domains) + " names" : "" }}
            <template v-if="lists.dead_weight_mb"> · {{ lists.dead_weight_mb }} MB earning nothing</template>
          </span>
        </div>
        <p class="sec-note">
          Judged over {{ lists.observed_hours || hours }} hours of real traffic. A
          threat feed that blocked nothing is doing its job and is marked
          protective — it is not judged on hit rate, because the outcome you paid
          for is a clean network.
        </p>
        <table class="tb">
          <thead>
            <tr>
              <th>List</th>
              <th class="r" style="width:96px">Names</th>
              <th class="r" style="width:96px">Blocked</th>
              <th class="r" style="width:80px">MB</th>
              <th style="width:130px">Verdict</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="l in listRows" :key="l.source">
              <td class="id">
                {{ l.source }}
                <span class="sub" v-if="l.note">{{ l.note }}</span>
              </td>
              <td class="r">{{ nf.format(l.domains) }}</td>
              <td class="r">{{ nf.format(l.blocks) }}</td>
              <td class="r">{{ l.est_mb }}</td>
              <td>
                <span class="vd" :class="l.verdict === 'dead weight' ? 'warn'
                  : l.verdict === 'earning' ? 'good' : 'calm'">{{ l.verdict }}</span>
                <span class="sub" v-if="l.protective">protective — not judged on hits</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="b-warn" v-if="err">{{ err }}</p>
    </div>
  </div>
</template>
