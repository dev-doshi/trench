<script setup lang="ts">
/* Privacy — what this machine remembers, and what leaves it.
 *
 * It used to be an accounting only: it showed the four recording levels and then
 * explained that changing one was a config-file edit. Stating a setting and
 * refusing to offer it is not restraint, it is a missing feature — the level is
 * now set here, and the page still says plainly what each one costs.
 */
import { computed, onMounted, ref } from "vue";
import { api } from "../lib/api";
import { store } from "../lib/store";
import Ico from "../ui/Ico.vue";

const nf = new Intl.NumberFormat();
const p = ref<any>(null);
const sys = ref<any>(null);
const loading = ref(true);
const err = ref("");
const confirming = ref(false);

async function load() {
  loading.value = true; err.value = "";
  try {
    const [a, b, st] = await Promise.all([
      api.get("/privacy"),
      api.get("/system").catch(() => null),
      api.get("/settings").catch(() => null),
    ]);
    p.value = a; sys.value = b;
    // Whether this is settable at all is known up front, so the choices can be
    // disabled with the reason rather than failing after a click.
    canSet.value = st ? !!st.writable : false;
    cannotWhy.value = st ? (st.why || "") : "The settings endpoint is unavailable.";
  } catch (e: any) {
    err.value = e?.message || "the privacy settings could not be read";
  } finally { loading.value = false; }
}
onMounted(load);

const saving = ref<number | null>(null);
const canSet = ref(true);
const cannotWhy = ref("");

/** Writes through the settings endpoint, which persists to the config file. */
async function setLevel(level: number) {
  if (level === p.value?.level) return;
  saving.value = level;
  try {
    await api.put("/settings", { changes: { "querylog.privacy_level": String(level) } });
    await load();
    store.toast("Recording level changed", p.value?.level_name || "");
  } catch (e: any) {
    store.toast("Unchanged", e?.message || "", true);
  } finally { saving.value = null; }
}

async function purge() {
  try {
    const r = await api.post("/querylog/purge");
    store.toast("Purged", `${nf.format(r.purged ?? 0)} rows deleted`);
    confirming.value = false;
    await load();
  } catch (e: any) {
    store.toast("Not purged", e?.message || "", true);
  }
}

/** The browser fetches it directly; this console never holds a copy. */
function exportLog() {
  window.location.href = "/api/v1/querylog/export";
}

const plaintext = computed(() => {
  const list: string[] = sys.value?.upstream || [];
  return list.filter((u) => !/^(tls|https|quic):\/\//.test(u));
});
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Privacy</h2>
    </header>

    <div class="vw-body">
      <div class="sec" v-if="p">
        <div class="sec-h"><h5 class="b-cap">What is recorded</h5></div>
        <div class="ev-big" style="margin-bottom:12px">
          <b>{{ p.enabled ? nf.format(p.stored_count) : "Nothing" }}</b>
          <span v-if="p.enabled">queries held right now</span>
          <span v-else>the query log is switched off entirely</span>
        </div>
        <dl class="kvs" v-if="p.enabled">
          <dt>Detail level</dt>
          <dd class="ui">{{ p.level_name }} — {{ p.level_description }}</dd>
          <dt>Retention</dt>
          <dd class="ui">
            {{ p.retention_days
              ? `${p.retention_days} day${p.retention_days === 1 ? "" : "s"}, then rows are deleted`
              : "kept until you purge them" }}
          </dd>
          <dt>Stored at</dt><dd>{{ p.db_path }}</dd>
          <dt>Survives a reboot</dt>
          <dd class="ui">
            {{ p.survives_reboot
              ? "yes — the file is on disk"
              : "no — held in memory only, and lost on restart" }}
          </dd>
        </dl>
      </div>

      <div class="sec" v-if="p?.levels?.length">
        <div class="sec-h"><h5 class="b-cap">What gets recorded</h5></div>
        <p class="st-warn" v-if="!canSet" style="margin-bottom:var(--b-3)">{{ cannotWhy }}</p>
        <div class="pv-levels">
          <button v-for="l in p.levels" :key="l.level"
                  :class="{ on: l.level === p.level, busy: saving === l.level }"
                  :disabled="saving !== null || !canSet"
                  :title="canSet ? '' : cannotWhy" @click="setLevel(l.level)">
            <b>{{ l.name }}</b>
            <em>{{ l.description }}</em>
          </button>
        </div>
      </div>

      <div class="sec">
        <div class="sec-h"><h5 class="b-cap">What leaves this machine</h5></div>
        <p class="b-warn" v-if="plaintext.length" style="margin:0 0 10px">
          {{ plaintext.length }} upstream{{ plaintext.length === 1 ? " carries" : "s carry" }}
          your queries in clear text: <code>{{ plaintext.join(", ") }}</code>. Any
          network between here and there sees every name, and can change the answer.
        </p>

      </div>

      <div class="sec" v-if="p?.enabled">
        <div class="sec-h"><h5 class="b-cap">Your copy of it</h5></div>
        <div class="row-acts">
          <button class="btn" @click="exportLog"><Ico name="copy" /> export as NDJSON</button>
          <button class="btn risk" v-if="!confirming" @click="confirming = true">
            delete every stored query
          </button>
          <template v-else>
            <span class="sec-note" style="margin:0">
              Deletes all {{ nf.format(p.stored_count) }} rows. This cannot be undone.
            </span>
            <button class="btn risk" @click="purge">delete them</button>
            <button class="btn" @click="confirming = false">keep them</button>
          </template>
        </div>
      </div>

      <p class="b-void-state" v-if="loading">Reading…</p>
      <p class="b-warn" v-if="err">{{ err }}</p>
    </div>
  </div>
</template>
