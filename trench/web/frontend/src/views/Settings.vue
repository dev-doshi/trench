<script setup lang="ts">
/* Settings — every knob the resolver actually has.
 *
 * The form is generated from the schema the API serves (`api/settings.py`), so
 * there is no second list here to drift out of date with the config model.
 * Saving writes the YAML config file and reloads it: the file is still the
 * source of truth and still hand-editable, it is just no longer the only way in.
 */
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api, setToken } from "../lib/api";
import { local } from "../lib/local";
import { store } from "../lib/store";
import Collection from "../ui/Collection.vue";
import Audit from "./Audit.vue";
import Jobs from "./Jobs.vue";
import Privacy from "./Privacy.vue";

interface Field {
  path: string; label: string; type: string; group: string; help: string;
  options: string[]; min: number | null; max: number | null;
  unit: string; restart: boolean; placeholder: string;
  secret?: boolean; readonly?: boolean;
}

const fields = ref<Field[]>([]);
/* Collections — zones, keys, devices, groups. Held beside the flat fields
 * rather than inside them: their value is a tree, so "is it dirty" is a
 * structural comparison and not a string one. */
const collections = ref<any[]>([]);
const csaved = ref<Record<string, any>>({});
const cdraft = ref<Record<string, any>>({});
const clone = (v: any) => JSON.parse(JSON.stringify(v ?? null));
const groups = ref<string[]>([]);
const saved = ref<Record<string, any>>({});   // what the server last confirmed
const draft = ref<Record<string, any>>({});   // what is in the form
const writable = ref(true);
const why = ref("");
const configPath = ref("");
const loading = ref(true);
const busy = ref(false);
const group = ref("Resolution");

/* The tab is in the URL (?tab=jobs), so the frame's jobs indicator, the palette
 * and a pasted link can all land on one tab, and back returns to the last one.
 * Jobs and Audit are records rather than knobs; they live here because they are
 * what you consult while changing the knobs, not where you go to watch traffic. */
const EXTRA = ["jobs", "audit", "access", "browser"];
const route = useRoute();
const router = useRouter();
const tabOf = (g: string) => (EXTRA.includes(g) ? g : g.toLowerCase());
function fromRoute() {
  const t = String(route.query.tab || "").toLowerCase();
  if (!t) return;
  if (EXTRA.includes(t)) { group.value = t; return; }
  const g = groups.value.find((x) => x.toLowerCase() === t);
  if (g) group.value = g;
  else if (!groups.value.length) group.value = t;   // resolved once the schema arrives
}
function pick(g: string) {
  group.value = g;
  if (String(route.query.tab || "") !== tabOf(g))
    router.replace({ query: { ...route.query, tab: tabOf(g) } });
}
watch(() => route.query.tab, fromRoute, { immediate: true });
const isForm = computed(() => !EXTRA.includes(group.value));

const token = ref(local.get("dg_token") || "");
const skin = ref(local.get("bw_skin") || "auto");

/* Access: API tokens and the second factor. Both live here rather than in the
 * generated form above, because neither is a config value — they are records in
 * the database, and a token is readable exactly once. */
interface Tok { id: number; name: string; scopes: string; owner: string; created: number; last_used: number; expires: number }
const tokens = ref<Tok[]>([]);
const newName = ref("");
const newScope = ref("viewer");
const minted = ref("");            // shown once, never fetched again
const totpOn = ref(false);
const totpSecret = ref("");        // during enrolment only
const totpUri = ref("");
const totpCode = ref("");
const totpOffCode = ref("");       // a current code: a session alone cannot turn it off

async function loadAccess() {
  try {
    tokens.value = (await api.get("/auth/tokens")).tokens;
    totpOn.value = (await api.get("/auth/me")).totp;
  } catch (e: any) {
    store.toast("Access unavailable", e?.message || "", true);
  }
}

async function mint() {
  const name = newName.value.trim();
  if (!name) return;
  try {
    const r = await api.post("/auth/tokens", { name, scope: newScope.value });
    minted.value = r.token;
    newName.value = "";
    await loadAccess();
  } catch (e: any) {
    store.toast("Token not created", e?.message || "", true);
  }
}

async function revoke(t: Tok) {
  try {
    await api.del(`/auth/tokens/${t.id}`);
    if (minted.value) minted.value = "";
    await loadAccess();
    store.toast("Token revoked", t.name);
  } catch (e: any) {
    store.toast("Not revoked", e?.message || "", true);
  }
}

async function startTotp() {
  try {
    const r = await api.post("/auth/totp/enrol");
    totpSecret.value = r.secret;
    totpUri.value = r.uri;
  } catch (e: any) {
    store.toast("Could not start enrolment", e?.message || "", true);
  }
}

async function confirmTotp() {
  try {
    await api.post("/auth/totp/confirm", { code: totpCode.value.trim() });
    totpSecret.value = ""; totpUri.value = ""; totpCode.value = "";
    await loadAccess();
    store.toast("Two-factor enabled", "keep a recovery plan: trench passwd --clear-totp");
  } catch (e: any) {
    store.toast("That code did not match", e?.message || "", true);
  }
}

async function disableTotp() {
  try {
    await api.del("/auth/totp", { code: totpOffCode.value.trim() });
    totpOffCode.value = "";
    await loadAccess();
    store.toast("Two-factor disabled");
  } catch (e: any) {
    store.toast("Not disabled", e?.message || "", true);
  }
}

const when = (t: number) => (t ? new Date(t * 1000).toLocaleDateString() : "never");

const asText = (f: Field, v: any) =>
  f.type === "list" ? (Array.isArray(v) ? v.join("\n") : (v ?? "")) : v;

async function load() {
  loading.value = true;
  try {
    const r = await api.get("/settings");
    fields.value = r.fields;
    groups.value = r.groups;
    writable.value = r.writable;
    why.value = r.why || "";
    configPath.value = r.config_path;
    saved.value = r.values;
    const d: Record<string, any> = {};
    for (const f of r.fields as Field[]) d[f.path] = asText(f, r.values[f.path]);
    draft.value = d;
    collections.value = r.collections || [];
    csaved.value = r.collection_values || {};
    cdraft.value = clone(r.collection_values || {});
    fromRoute();
    if (!EXTRA.includes(group.value) && !groups.value.includes(group.value))
      group.value = groups.value[0] || "Resolution";
  } catch (e: any) {
    store.toast("Settings unavailable", e?.message || "", true);
  } finally { loading.value = false; }
}
onMounted(async () => { await load(); await loadAccess(); });

const shown = computed(() => fields.value.filter((f) => f.group === group.value));
const shownCollections = computed(() =>
  collections.value.filter((c) => c.group === group.value));

/** Collections whose tree differs from what the server confirmed. */
const cdirty = computed(() =>
  collections.value.map((c) => c.path)
    .filter((p) => JSON.stringify(cdraft.value[p]) !== JSON.stringify(csaved.value[p])));

/** Paths whose form value differs from what the server confirmed. */
const dirty = computed(() => {
  const out: string[] = [];
  for (const f of fields.value) {
    if (f.readonly) continue;
    const a = draft.value[f.path];
    const b = asText(f, saved.value[f.path]);
    const same = f.type === "list"
      ? String(a ?? "").trim() === String(b ?? "").trim()
      : String(a) === String(b);
    if (!same) out.push(f.path);
  }
  return out;
});

const dirtyIn = (g: string) =>
  dirty.value.some((p) => fields.value.find((f) => f.path === p)?.group === g) ||
  cdirty.value.some((p) => collections.value.find((c) => c.path === p)?.group === g);

const totalDirty = computed(() => dirty.value.length + cdirty.value.length);

async function save() {
  if (!totalDirty.value) return;
  busy.value = true;
  const changes: Record<string, any> = {};
  for (const p of dirty.value) changes[p] = draft.value[p];
  for (const p of cdirty.value) changes[p] = cdraft.value[p];
  const n = totalDirty.value;
  try {
    const r = await api.put("/settings", { changes });
    store.toast(`Saved ${n} setting${n > 1 ? "s" : ""}`,
                r.restart?.length ? `applied on restart: ${r.restart.join(", ")}` : "");
    await load();
  } catch (e: any) {
    store.toast("Not saved", e?.message || "", true);
  } finally { busy.value = false; }
}

function revert() {
  for (const f of fields.value) draft.value[f.path] = asText(f, saved.value[f.path]);
  cdraft.value = clone(csaved.value);
}

function setSkin(v: string) {
  skin.value = v;
  document.documentElement.dataset.skin = v;
  local.set("bw_skin", v);
}

function saveTokenValue() {
  setToken(token.value.trim() || null);
  store.toast(token.value.trim() ? "Token stored" : "Token cleared", "this browser only");
}
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Settings</h2>
      <div class="acts" v-if="isForm || totalDirty">
        <span class="st-dirty" v-if="totalDirty">{{ totalDirty }} unsaved</span>
        <button class="btn" v-if="totalDirty" @click="revert">revert</button>
        <button class="btn primary" :disabled="!totalDirty || busy || !writable" @click="save">
          {{ busy ? "saving…" : "save" }}
        </button>
      </div>
    </header>

    <!-- The tab strip sits in the chrome, so switching groups never moves
         anything above the form. -->
    <nav class="st-tabs">
      <button v-for="g in groups" :key="g" :class="{ on: g === group }" @click="pick(g)">
        {{ g }}<i v-if="dirtyIn(g)" />
      </button>
      <span class="st-tabs-gap" aria-hidden="true" />
      <button :class="{ on: group === 'jobs' }" @click="pick('jobs')">Jobs</button>
      <button :class="{ on: group === 'audit' }" @click="pick('audit')">Audit</button>
      <button :class="{ on: group === 'access' }" @click="pick('access')">Access</button>
      <button :class="{ on: group === 'browser' }" @click="pick('browser')">This browser</button>
    </nav>

    <div class="vw-body">
      <p class="st-warn" v-if="!writable && !loading && isForm">{{ why }}</p>

      <Jobs v-if="group === 'jobs'" embedded />
      <Audit v-else-if="group === 'audit'" embedded />
      <Privacy v-if="group === 'Privacy'" embedded />

      <div class="st-form" v-if="isForm">
        <label class="st-row" v-for="f in shown" :key="f.path">
          <span class="st-lbl">
            {{ f.label }}
            <em v-if="f.help">{{ f.help }}</em>
          </span>

          <span class="st-ctl">
            <!-- state the file cannot set: shown as what it is, not as a
                 control that would be ignored -->
            <em v-if="f.readonly" class="st-ro">{{ saved[f.path] ? "armed" : "not armed" }}</em>

            <input v-else-if="f.type === 'bool'" type="checkbox" class="sw" v-model="draft[f.path]" />

            <select v-else-if="f.type === 'select'" v-model="draft[f.path]">
              <option v-for="o in f.options" :key="o" :value="o">{{ o }}</option>
            </select>

            <textarea v-else-if="f.type === 'list'" v-model="draft[f.path]" rows="4"
                      :placeholder="f.placeholder" spellcheck="false" />

            <input v-else-if="f.type === 'int' || f.type === 'float'" type="number"
                   v-model="draft[f.path]" :min="f.min ?? undefined" :max="f.max ?? undefined"
                   :step="f.type === 'float' ? 'any' : 1" />

            <input v-else :type="f.secret ? 'password' : 'text'" v-model="draft[f.path]"
                   :placeholder="f.secret ? 'unchanged' : f.placeholder"
                   :autocomplete="f.secret ? 'new-password' : undefined" />

            <u v-if="f.unit">{{ f.unit }}</u>
            <b v-if="f.restart" title="saved now, applied on restart">restart</b>
          </span>
        </label>
        <Collection v-for="c in shownCollections" :key="c.path" :spec="c"
                    v-model="cdraft[c.path]" />

        <p class="st-path" v-if="configPath">Saved to <code>{{ configPath }}</code></p>
      </div>

      <div class="st-form" v-else-if="group === 'access'">
        <label class="st-row">
          <span class="st-lbl">
            API tokens
            <em>For scripts and the <code>trench</code> CLI. A token is shown once.</em>
          </span>
          <span class="st-ctl">
            <input type="text" v-model="newName" placeholder="what is it for"
                   style="width:200px" @keyup.enter="mint" />
            <select v-model="newScope">
              <option value="viewer">viewer — read only</option>
              <option value="editor">editor — can change rules</option>
              <option value="admin">admin — everything</option>
            </select>
            <button class="btn primary" :disabled="!newName.trim()" @click="mint">create</button>
          </span>
        </label>

        <p class="st-minted" v-if="minted">
          Copy this now — it is not stored and cannot be shown again.
          <code>{{ minted }}</code>
        </p>

        <table class="st-toks" v-if="tokens.length">
          <thead>
            <tr><th>name</th><th>scope</th><th>owner</th><th>created</th><th>last used</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="t in tokens" :key="t.id">
              <td>{{ t.name }}</td>
              <td>{{ t.scopes }}</td>
              <td>{{ t.owner }}</td>
              <td>{{ when(t.created) }}</td>
              <td>{{ when(t.last_used) }}</td>
              <td><button class="btn" @click="revoke(t)">revoke</button></td>
            </tr>
          </tbody>
        </table>
        <p class="st-none" v-else>No tokens yet.</p>

        <label class="st-row">
          <span class="st-lbl">
            Two-factor
            <em v-if="totpOn">On. Lost your authenticator? <code>trench passwd --clear-totp</code> on the box.</em>
            <em v-else>A code from an authenticator app, on top of the password.</em>
          </span>
          <span class="st-ctl" v-if="totpOn">
            <input type="text" v-model="totpOffCode" placeholder="current code" inputmode="numeric"
                   autocomplete="one-time-code" style="width:120px" @keyup.enter="disableTotp" />
            <button class="btn" :disabled="!totpOffCode.trim()" @click="disableTotp">turn off</button>
          </span>
          <span class="st-ctl" v-else>
            <button class="btn" v-if="!totpSecret" @click="startTotp">set up</button>
          </span>
        </label>

        <div class="st-totp" v-if="totpSecret">
          <p>Add this secret to your authenticator, then enter the code it shows.
             Nothing is stored until the code matches.</p>
          <code>{{ totpSecret }}</code>
          <span class="st-ctl">
            <input type="text" v-model="totpCode" placeholder="000000" inputmode="numeric"
                   style="width:100px" @keyup.enter="confirmTotp" />
            <button class="btn primary" @click="confirmTotp">confirm</button>
          </span>
        </div>
      </div>

      <div class="st-form" v-else-if="group === 'browser'">
        <label class="st-row">
          <span class="st-lbl">
            Appearance
            <em>Auto follows this device's light or dark setting.</em>
          </span>
          <span class="st-ctl">
            <span class="seg">
              <button :class="{ on: skin === 'auto' }" @click="setSkin('auto')">auto</button>
              <button :class="{ on: skin === 'night' }" @click="setSkin('night')">night</button>
              <button :class="{ on: skin === 'day' }" @click="setSkin('day')">day</button>
            </span>
          </span>
        </label>
        <label class="st-row">
          <span class="st-lbl">
            API token
            <em>For scripts. Kept in this browser only.</em>
          </span>
          <span class="st-ctl">
            <input type="password" v-model="token" placeholder="paste a token" style="width:280px" />
            <button class="btn" @click="saveTokenValue">save</button>
          </span>
        </label>
      </div>
    </div>
  </div>
</template>
