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
 *
 * It is also the one place per-client policy can be *changed*. The API has had
 * client CRUD all along and nothing in the console used it, so exempting a
 * device from filtering — the single most common thing anyone wants to do to
 * one device — meant hand-writing JSON. A page that shows a device's blocked
 * share and cannot act on it is a report, not a console.
 */
import { computed, nextTick, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { api } from "../lib/api";
import { registrable } from "../lib/dnsname";
import { entryOf, nameOf, nameTitle, useNames } from "../lib/names";
import { kindOf } from "../lib/outcome";
import type { Row } from "../lib/qlang";
import { store } from "../lib/store";
import Spine from "../ui/Spine.vue";

const router = useRouter();
const nf = new Intl.NumberFormat();
useNames();

const managed = ref<any[]>([]);
const groups = ref<any[]>([]);
const rows = ref<Row[]>([]);
const loading = ref(true);
const err = ref("");
/** Addresses with a policy write in flight, so a row cannot be double-sent. */
const busy = ref(new Set<string>());
/** Per-row failure, shown in the line that is already there — a message that
 *  adds a line would move every row below it, which is the one thing a table
 *  being scanned must never do. */
const note = ref<Record<string, string>>({});

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

/** The managed entry's policy, which the API hands back as a JSON string. */
function policyOf(c: any): Record<string, any> {
  if (!c) return {};
  try {
    return typeof c.policy === "string" ? JSON.parse(c.policy || "{}") : (c.policy || {});
  } catch {
    return {};
  }
}

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
    // A name you gave wins; otherwise Trench's lease or the router's reverse
    // lookup. Those are the device's own claim, so the row says so.
    const found = c?.name ? undefined : entryOf(e.ip);
    return {
      ...e,
      managed: c || null,
      // No entry at all means the household policy applies, which is filtered.
      filtered: c ? policyOf(c).block !== false : true,
      name: c?.name || found?.name || "",
      manualName: c?.name || "",
      identBy: c?.name ? c.ident_type || "" : found ? FOUND_BY[found.source] || "" : c?.ident_type || "",
      // The group lives in the policy: that is what `client_from_row` reads.
      group: String(policyOf(c).group || ""),
      vocabN: e.vocab.size,
      blockedPct: Math.round((e.blocked / Math.max(1, e.total)) * 100),
      by: { cache: e.cache, upstream: e.upstream, local: e.local,
            blocked: e.blocked, failed: e.failed, unknown: e.unknown },
    };
  });
  return out.sort((a, b) => b.total - a.total);
});

/** How a name that you did not type was learned. */
const FOUND_BY: Record<string, string> = {
  manual: "named in the config", dhcp: "DHCP lease", network: "named by the router" };

const max = computed(() => Math.max(1, ...table.value.map((t) => t.total)));
/* Find: a household has dozens of devices, and the one you want is "the
 * printer", not whatever sorts first by query count. */
const find = ref("");
const matches = (t: any) => {
  const q = find.value.trim().toLowerCase();
  return !q || t.name.toLowerCase().includes(q) || t.ip.includes(q) || t.group.toLowerCase().includes(q);
};
const named = computed(() => table.value.filter((t) => t.name && matches(t)));
const unnamed = computed(() => table.value.filter((t) => !t.name && matches(t)));
const groupNames = computed(() => groups.value.map((g) => g.name as string));

/** Who is in each group, as far as the console can change it: devices put there
 *  from here. Members declared in the config file are listed by the API and are
 *  shown, but only the file can take them out. */
const membersOf = (g: string) => table.value.filter((t) => t.group === g);
const fileMembers = (g: any) => {
  const here = new Set(membersOf(g.name).map((t) => t.name || t.ip));
  return (g.clients || []).filter((c: string) => !here.has(c) && !here.has(nameOf(c) || c));
};
const candidates = (g: string) => table.value.filter((t) => t.group !== g);

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

/**
 * Turn filtering on or off for one device.
 *
 * A device with no managed entry gets one; a device that has one keeps it, and
 * the rest of its policy with it — turning filtering back on by deleting the
 * row would throw away its name, its group and every other override it carries.
 */
async function setFiltering(d: any, on: boolean) {
  await write(d, { policy: { block: on } });
}

/**
 * Change one device's entry: a policy patch merged over what it has, and/or a
 * name. The same rule as filtering — a device without an entry gets one, and a
 * device with one keeps everything the patch does not mention. A key patched to
 * `undefined` is removed (that is how a device leaves a group).
 */
async function write(d: any, patch: { policy?: Record<string, any>; name?: string }): Promise<boolean> {
  const ip = d.ip;
  if (busy.value.has(ip)) return false;
  busy.value = new Set(busy.value).add(ip);
  note.value = { ...note.value, [ip]: "" };
  try {
    if (d.managed) {
      const body: Record<string, any> = {};
      if (patch.policy) body.policy = { ...policyOf(d.managed), ...patch.policy };
      if (patch.name !== undefined) body.name = patch.name;
      await api.put(`/clients/manage/${d.managed.id}`, body);
    } else {
      await api.post("/clients/manage",
                     { ident: ip, ident_type: "ip", name: patch.name ?? d.manualName ?? "",
                       policy: patch.policy || {} });
    }
    const [fresh, g] = await Promise.all([
      api.get("/clients/manage"), api.get("/groups").catch(() => null)]);
    managed.value = fresh.clients || [];
    if (g) groups.value = g.groups || [];
    return true;
  } catch (e: any) {
    // Every control is bound to the loaded state, so it springs back on its own.
    note.value = { ...note.value, [ip]: e?.message || "could not be saved" };
    store.toast("Not saved", e?.message || "", true);
    return false;
  } finally {
    const s = new Set(busy.value);
    s.delete(ip);
    busy.value = s;
  }
}

async function setGroup(d: any, g: string) {
  if ((d.group || "") === g) return;
  const who = d.name || d.ip;
  if (await write(d, { policy: { group: g || undefined } }))
    store.toast(g ? `${who} is now in ${g}` : `${who} is back on the household policy`,
                "applies to its next query");
}

/* Naming in place. The "not identified" section calls itself a queue of work,
 * and until now there was nothing in it to do the work with. */
const editing = ref("");
const draftName = ref("");
async function startName(d: any) {
  editing.value = d.ip;
  draftName.value = d.manualName || d.name || "";
  await nextTick();
  (document.querySelector(".dv-name input") as HTMLInputElement | null)?.select();
}
async function saveName(d: any) {
  const n = draftName.value.trim();
  if (editing.value !== d.ip) return;
  editing.value = "";
  if (n === (d.manualName || "")) return;
  if (await write(d, { name: n }))
    store.toast(n ? `Named ${d.ip}` : `Name cleared for ${d.ip}`, n);
}

function browse(ip: string) {
  router.push({ path: "/browse", query: { p: "device,domain,name", s: ip } });
}
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Devices</h2>
      <div class="acts">
        <input class="dv-find" v-model="find" type="search" placeholder="find a device, address or group"
               @keydown.esc="find = ''" />
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
              <th style="width:20%">Outcomes</th>
              <th style="width:150px" v-if="groupNames.length">Group</th>
              <th style="width:112px">Filtering</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in named" :key="d.ip" class="click" @click="editing !== d.ip && browse(d.ip)">
              <td class="id" :title="nameTitle(d.ip)">
                <span class="dv-name" v-if="editing === d.ip" @click.stop>
                  <input v-model="draftName" maxlength="64" placeholder="a name you will recognise"
                         @keydown.enter="saveName(d)" @keydown.esc="editing = ''" @blur="saveName(d)" />
                </span>
                <span class="dv-named" v-else>
                  <span class="dev" style="max-width:260px">{{ d.name }}</span>
                  <button class="dv-edit" @click.stop="startName(d)"
                          :title="d.manualName ? 'Rename this device' : 'Give it your own name instead of the one it claims'">rename</button>
                </span>
                <span class="sub">
                  {{ d.ip }} · {{ d.identBy || "not identified" }} · {{ ago(d.last) }}
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
              <td v-if="groupNames.length" @click.stop>
                <select class="dv-group" :value="d.group" :disabled="busy.has(d.ip)"
                        @change="setGroup(d, ($event.target as HTMLSelectElement).value)">
                  <option value="">Household</option>
                  <option v-for="g in groupNames" :key="g" :value="g">{{ g }}</option>
                  <option v-if="d.group && !groupNames.includes(d.group)" :value="d.group">{{ d.group }} (not configured)</option>
                </select>
              </td>
              <td class="filt" @click.stop>
                <label class="sw-cell" :title="d.filtered
                    ? 'Filtering is on for this device'
                    : 'This device is exempt: blocklists, CNAME-cloak inspection and address lists are all skipped for it'">
                  <input type="checkbox" class="sw" :checked="d.filtered"
                         :disabled="busy.has(d.ip)"
                         @change="setFiltering(d, ($event.target as HTMLInputElement).checked)" />
                  <span class="sub">{{ note[d.ip] || (d.filtered ? "on" : "exempt") }}</span>
                </label>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="b-void-state" v-else-if="!loading">
          {{ find ? `No named device matches “${find}”.` : "No device has a name yet." }}
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
              <th style="width:22%">Outcomes</th>
              <th style="width:150px" v-if="groupNames.length">Group</th>
              <th style="width:112px">Filtering</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in unnamed" :key="d.ip" class="click" @click="editing !== d.ip && browse(d.ip)">
              <td class="id">
                <span class="dv-name" v-if="editing === d.ip" @click.stop>
                  <input v-model="draftName" maxlength="64" placeholder="name it"
                         @keydown.enter="saveName(d)" @keydown.esc="editing = ''" @blur="saveName(d)" />
                </span>
                <span class="dv-named" v-else>
                  {{ d.ip }}
                  <button class="dv-edit" @click.stop="startName(d)">name it</button>
                </span>
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
              <td v-if="groupNames.length" @click.stop>
                <select class="dv-group" :value="d.group" :disabled="busy.has(d.ip)"
                        @change="setGroup(d, ($event.target as HTMLSelectElement).value)">
                  <option value="">Household</option>
                  <option v-for="g in groupNames" :key="g" :value="g">{{ g }}</option>
                  <option v-if="d.group && !groupNames.includes(d.group)" :value="d.group">{{ d.group }} (not configured)</option>
                </select>
              </td>
              <td class="filt" @click.stop>
                <label class="sw-cell" :title="d.filtered
                    ? 'Filtering is on for this device'
                    : 'This device is exempt: blocklists, CNAME-cloak inspection and address lists are all skipped for it'">
                  <input type="checkbox" class="sw" :checked="d.filtered"
                         :disabled="busy.has(d.ip)"
                         @change="setFiltering(d, ($event.target as HTMLInputElement).checked)" />
                  <span class="sub">{{ note[d.ip] || (d.filtered ? "on" : "exempt") }}</span>
                </label>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Groups</h5>
          <span class="b-cap">{{ groups.length }}</span>
          <div class="acts">
            <RouterLink class="btn" to="/settings?tab=filtering"
                        title="Groups are declared with their own lists under Settings → Filtering → Filter groups">
              define groups
            </RouterLink>
          </div>
        </div>
        <table class="tb" v-if="groups.length">
          <thead><tr><th style="width:18%">Group</th><th>Devices</th><th style="width:24%">Rules</th></tr></thead>
          <tbody>
            <tr v-for="g in groups" :key="g.name">
              <td class="id">{{ g.name }}</td>
              <td>
                <div class="dv-members">
                  <span class="dv-chip" v-for="m in membersOf(g.name)" :key="m.ip" :title="m.ip">
                    <span class="dev">{{ m.name || m.ip }}</span>
                    <button :disabled="busy.has(m.ip)" @click="setGroup(m, '')"
                            :aria-label="`Take ${m.name || m.ip} out of ${g.name}`" title="take it out of this group">×</button>
                  </span>
                  <span class="dv-chip file" v-for="c in fileMembers(g)" :key="'f' + c"
                        title="Declared in the config file; only the file can take it out">
                    <span class="dev">{{ nameOf(c) || c }}</span>
                  </span>
                  <select class="dv-add" value="" @change="(e) => {
                            const el = e.target as HTMLSelectElement;
                            const d = table.find((t) => t.ip === el.value);
                            el.value = '';
                            if (d) setGroup(d, g.name);
                          }">
                    <option value="" disabled>add a device…</option>
                    <option v-for="d in candidates(g.name)" :key="d.ip" :value="d.ip">
                      {{ d.name ? `${d.name} · ${d.ip}` : d.ip }}{{ d.group ? ` (from ${d.group})` : "" }}
                    </option>
                  </select>
                </div>
              </td>
              <td>
                <span v-if="g.compiled">{{ nf.format(g.rules) }} own<span v-if="g.inherit">, plus the household's</span></span>
                <span v-else class="b-warn">lists did not compile</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="b-void-state" v-else-if="!loading">
          No groups yet. A group is a set of devices with its own lists — stricter
          for the children's tablets, lighter for a work laptop. Define one under
          Settings → Filtering, then put devices in it here.
        </p>
      </div>

      <p class="b-void-state" v-if="loading">Reading the last day…</p>
      <p class="b-warn" v-if="err">{{ err }}</p>
    </div>
  </div>
</template>
