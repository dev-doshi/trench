<script setup lang="ts">
/* Policy — the rules, read back by what they do.
 *
 * A list of rules in a textarea tells you what you typed. It does not tell you
 * what your policy *does*, which is the only thing that matters, and it is why
 * every self-hosted filter eventually accumulates rules nobody dares delete.
 *
 * Three decisions:
 *   · every rule is rendered as a sentence with its syntax beneath it. The most
 *     common policy bug is a rule that does something other than what its author
 *     believed, and reading it back in English is the cheapest possible defence
 *   · nothing is committed without being tried. The draft box runs against the
 *     recorded log through /whatif and reports the exact names that would change
 *     outcome — separated into "already blocked" and "answered until now",
 *     because the second set is the breakage
 *   · a rule's effect is shown next to it: how many queries it actually decided
 *     in the loaded window. A rule that has never fired is not necessarily wrong,
 *     but you should be able to see that it has never fired
 */
import { computed, onMounted, ref } from "vue";
import { api } from "../lib/api";
import { kindOf } from "../lib/outcome";
import type { Row } from "../lib/qlang";
import { store } from "../lib/store";
import Ico from "../ui/Ico.vue";

const nf = new Intl.NumberFormat();
const deny = ref<string[]>([]);
const allow = ref<string[]>([]);
const imported = ref(0);
const rows = ref<Row[]>([]);
const loading = ref(true);
const err = ref("");

const draft = ref("");
const draftKind = ref<"deny" | "allow">("deny");
const trial = ref<any>(null);
const trying = ref(false);

async function load() {
  loading.value = true;
  try {
    const r = await api.get("/rules");
    deny.value = r.deny || [];
    allow.value = r.allow || [];
    imported.value = r.imported || 0;
    // a window of real traffic, so each rule can be shown with its effect
    const until = Date.now() * 1000;
    const q = await api.get("/querylog" + api.qs({ since: until - 24 * 3600e6, until, limit: 1000 }));
    rows.value = q.rows || [];
  } catch (e: any) {
    err.value = e?.message || "the rules could not be read";
  } finally { loading.value = false; }
}
onMounted(load);

/** How many loaded queries each rule actually decided. */
const firedBy = computed(() => {
  const m = new Map<string, { hits: number; names: Set<string> }>();
  for (const r of rows.value) {
    if (!r.rule) continue;
    let e = m.get(r.rule);
    if (!e) { e = { hits: 0, names: new Set() }; m.set(r.rule, e); }
    e.hits++;
    e.names.add(r.qname.toLowerCase());
  }
  return m;
});

/**
 * Render a rule as a sentence.
 *
 * What this endpoint accepts is a bare domain, applied as a suffix — the name and
 * everything under it. It is not the full filter syntax, so the sentence says
 * exactly that rather than implying a precision the rule does not have. If a line
 * looks like filter syntax, it is named as such and refused for commit instead of
 * being quietly lowercased into a domain that means something else.
 */
function looksLikeSyntax(line: string): boolean {
  return /[|^$@*/]/.test(line.trim());
}

function sentence(rule: string, kind: "deny" | "allow"): string {
  const r = rule.trim().toLowerCase();
  if (!r) return "";
  if (r.startsWith("!") || r.startsWith("#")) return "A comment — no effect.";
  if (looksLikeSyntax(r)) {
    return "Filter syntax. It can be tried below, but this screen commits plain "
      + "domains only — syntax rules belong in a list file the resolver loads.";
  }
  return kind === "allow"
    ? `Allow ${r} and everything under it, overriding any list that refuses it.`
    : `Block ${r} and everything under it.`;
}

const lines = computed(() =>
  draft.value.split("\n").map((l) => l.trim()).filter(Boolean));
const plain = computed(() => lines.value.filter((l) => !looksLikeSyntax(l)));
const syntax = computed(() => lines.value.filter((l) => looksLikeSyntax(l)));

/* The trial takes both: /whatif compiles full syntax through `list_text`, so a
 * syntax rule can be evaluated even though this screen will not commit it. */
async function tryDraft() {
  if (!lines.value.length) return;
  trying.value = true;
  try {
    const body: Record<string, unknown> = { list_text: syntax.value.join("\n") };
    body[draftKind.value] = plain.value;
    trial.value = await api.post("/whatif", body);
  } catch (e: any) {
    store.toast("Trial failed", e?.message || "", true);
  } finally { trying.value = false; }
}

/* One call per domain: that is the endpoint's contract, and batching it here
 * would only hide which one failed. */
async function commit() {
  if (!plain.value.length) return;
  let done = 0;
  for (const domain of plain.value) {
    try {
      await api.post("/rules", { domain, action: draftKind.value });
      done++;
    } catch (e: any) {
      store.toast("Stopped at " + domain, e?.message || "", true);
      break;
    }
  }
  if (done) {
    store.toast("Committed", `${done} domain${done === 1 ? "" : "s"}`);
    draft.value = ""; trial.value = null;
    await load();
  }
}

async function remove(rule: string) {
  try {
    await api.post("/rules", { domain: rule, action: "remove" });
    store.toast("Removed", rule);
    await load();
  } catch (e: any) {
    store.toast("Not removed", e?.message || "", true);
  }
}

const newlyBlocked = computed(() => trial.value?.newly_blocked || []);
const newlyAllowed = computed(() => trial.value?.newly_allowed || []);

/** Of the names a draft would newly block, which were being answered? */
const wouldBreak = computed(() => {
  const answered = new Set(rows.value.filter((r) => kindOf(r) !== "blocked")
    .map((r) => r.qname.toLowerCase()));
  return newlyBlocked.value.filter((f: any) => answered.has(String(f.qname).toLowerCase()));
});
</script>

<template>
  <div class="vw">
    <header class="vw-head">
      <h2>Policy</h2>
      <div class="acts">
        <button class="btn" @click="load">reload</button>
      </div>
    </header>

    <div class="vw-body">
      <!-- draft first: the thing you came here to do -->
      <div class="sec">
        <div class="sec-h">
          <h5 class="b-cap">Draft a rule</h5>
          <span class="b-cap"></span>
        </div>
        <div style="display:flex;gap:10px;margin-bottom:10px">
          <button class="btn" :class="{ hard: draftKind === 'deny' }" @click="draftKind = 'deny'">
            <Ico name="held" /> block
          </button>
          <button class="btn" :class="{ hard: draftKind === 'allow' }" @click="draftKind = 'allow'">
            <Ico name="kept" /> allow
          </button>
        </div>
        <textarea class="ta" v-model="draft" spellcheck="false"
                  placeholder="telemetry.example.com&#10;metrics.vendor.example&#10;one domain per line — the name and everything under it" />
        <div class="row-acts" style="margin-top:10px">
          <button class="btn" @click="tryDraft" :disabled="trying || !draft.trim()">
            <Ico name="levels" /> {{ trying ? "trying…" : "try against the log" }}
          </button>
          <button class="btn hard" @click="commit" :disabled="!plain.length">
            commit {{ plain.length || "" }} {{ plain.length === 1 ? "domain" : "domains" }}
          </button>
          <span class="b-cap" v-if="syntax.length">
            {{ syntax.length }} syntax {{ syntax.length === 1 ? "line" : "lines" }} can be
            tried but not committed here
          </span>
        </div>

        <p class="sec-note" v-for="l in lines" :key="l" style="margin:10px 0 0">
          {{ sentence(l, draftKind) }}
          <code style="display:block;margin-top:2px">{{ l }}</code>
        </p>

        <!-- the trial result: the second set is the breakage -->
        <div v-if="trial" style="margin-top:18px">
          <dl class="kvs">
            <dt>Names considered</dt><dd class="ui">{{ nf.format(trial.total_names || 0) }}</dd>
            <dt>Queries affected</dt><dd class="ui">{{ nf.format(trial.affected_hits || 0) }}</dd>
          </dl>
          <div class="cols" style="margin-top:14px">
            <div v-if="newlyBlocked.length">
              <h5 class="b-cap" style="margin-bottom:8px">Would newly block</h5>
              <table class="tb">
                <thead><tr><th>Name</th><th class="r" style="width:90px">Queries</th></tr></thead>
                <tbody>
                  <tr v-for="f in newlyBlocked.slice(0, 25)" :key="f.qname">
                    <td class="id">{{ f.qname }}</td>
                    <td class="r">{{ nf.format(f.hits) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-if="newlyAllowed.length">
              <h5 class="b-cap" style="margin-bottom:8px">Would newly answer</h5>
              <table class="tb">
                <thead><tr><th>Name</th><th class="r" style="width:90px">Queries</th></tr></thead>
                <tbody>
                  <tr v-for="f in newlyAllowed.slice(0, 25)" :key="f.qname">
                    <td class="id">{{ f.qname }}</td>
                    <td class="r">{{ nf.format(f.hits) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <p class="b-warn" v-if="wouldBreak.length" style="margin-top:12px">
            {{ wouldBreak.length }} of those
            {{ wouldBreak.length === 1 ? "name is" : "names are" }} being answered
            right now — {{ wouldBreak.slice(0, 4).map((f: any) => f.qname).join(", ") }}.
            That set is where breakage comes from; the rest was already refused.
          </p>
          <p class="sec-note" v-if="!newlyBlocked.length && !newlyAllowed.length">
            This rule would not change the outcome of anything in the recorded log.
            Either it is already covered by an existing rule, or nothing has asked
            for what it matches.
          </p>
        </div>
      </div>

      <!-- the rules you have -->
      <div class="sec" v-for="set in [
        { kind: 'deny' as const, title: 'Blocking', list: deny },
        { kind: 'allow' as const, title: 'Allowing', list: allow }]" :key="set.kind">
        <div class="sec-h">
          <h5 class="b-cap">{{ set.title }}</h5>
          <span class="b-cap">{{ set.list.length }}</span>
        </div>
        <div v-if="set.list.length">
          <div v-for="r in set.list" :key="r"
               style="padding:11px 0;border-bottom:1px solid var(--b-edge-soft)">
            <div style="display:flex;gap:12px;align-items:baseline">
              <p class="sec-note" style="margin:0;flex:1">{{ sentence(r, set.kind) }}</p>
              <span class="b-cap" v-if="firedBy.get(r)">
                decided {{ nf.format(firedBy.get(r)!.hits) }} in 24h
              </span>
              <span class="b-cap" v-else style="color:var(--b-ink-4)">has not fired in 24h</span>
              <button class="btn-q" @click="remove(r)">remove</button>
            </div>
            <code class="mono" style="display:block;margin-top:3px">{{ r }}</code>
          </div>
        </div>
        <p class="b-void-state" v-else>
          You have written no {{ set.kind === "deny" ? "blocks" : "exceptions" }}.
          {{ set.kind === "allow"
            ? "Exceptions are how you keep a device working without weakening the policy for everything else."
            : "Downloaded lists cover most of what a filter needs; these are for the things only you know about." }}
        </p>
      </div>

      <p class="b-warn" v-if="err">{{ err }}</p>
    </div>
  </div>
</template>
