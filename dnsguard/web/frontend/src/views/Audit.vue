<script setup lang="ts">
/* Audit — who changed what.
 *
 * A timeline rather than a table, because these rows are read in one direction
 * and the question is always "what happened before this went wrong". A sortable
 * table invites you to reorder events, which is exactly the wrong affordance for
 * a causal record.
 *
 * Each entry says what was done in plain words and shows the raw action string
 * beneath it, so the record stays greppable while being readable.
 */
import { computed, onMounted, ref } from "vue";
import { api } from "../lib/api";
import { store } from "../lib/store";

const rows = ref<any[]>([]);
const loading = ref(true);
const err = ref("");
const me = computed(() => store.state.user?.name || "");

async function load() {
  loading.value = true; err.value = "";
  try {
    const r = await api.get("/audit" + api.qs({ limit: 300 }));
    rows.value = r.audit || [];
  } catch (e: any) {
    err.value = e?.message || "the audit log could not be read";
  } finally { loading.value = false; }
}
onMounted(load);

/** Plain words for the action strings the backend records. */
const WORDS: Record<string, (t: string) => string> = {
  "rule.deny": (t) => `started refusing ${t} and everything under it`,
  "rule.allow": (t) => `made an exception for ${t}`,
  "rule.remove": (t) => `removed the rule for ${t}`,
  "cache.flush": () => "emptied the cache",
  "gravity.refresh": () => "started a blocklist refresh",
  "querylog.purge": (t) => `deleted ${t} stored queries`,
  "toggle": (t) => `switched filtering ${t}`,
  "client.create": (t) => `named a device: ${t}`,
  "client.update": (t) => `changed a device: ${t}`,
  "client.delete": (t) => `removed a device: ${t}`,
  "group.create": (t) => `created the group ${t}`,
  "group.delete": (t) => `deleted the group ${t}`,
  "auth.login": () => "signed in",
  "auth.logout": () => "signed out",
};

function words(r: any): string {
  const f = WORDS[r.action];
  return f ? f(String(r.target ?? "")) : `${r.action} ${r.target ?? ""}`.trim();
}

const stamp = (ts: number) => {
  // the backend stores seconds for audit rows
  const d = new Date((ts > 1e12 ? ts / 1000 : ts * 1000));
  return d.toLocaleString();
};
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Audit</h2>
      <div class="acts"><button class="btn" @click="load">reload</button></div>
    </header>

    <div class="vw-body">
      <div class="sec">
        <div class="tl" v-if="rows.length">
          <div class="tl-i" v-for="(r, i) in rows" :key="i" :class="{ mine: r.user === me }">
            <div style="display:flex;gap:12px;align-items:baseline;flex-wrap:wrap">
              <span class="tl-w">{{ r.user || "someone" }} {{ words(r) }}</span>
              <span class="tl-t" style="margin-left:auto">{{ stamp(r.ts) }}</span>
            </div>
            <div class="tl-m">
              {{ r.action }}<template v-if="r.target"> · {{ r.target }}</template><template v-if="r.detail"> · {{ r.detail }}</template>
            </div>
          </div>
        </div>
        <p class="b-void-state" v-else-if="!loading">
          Nothing has been changed through the console. Edits made directly to the
          config file do not appear here — this records what came through the API.
        </p>
        <p class="b-void-state" v-if="loading">Reading…</p>
        <p class="b-warn" v-if="err">{{ err }}</p>
      </div>
    </div>
  </div>
</template>
