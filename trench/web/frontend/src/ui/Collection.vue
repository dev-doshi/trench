<script setup lang="ts">
/* One editable collection: zones, TSIG keys, local records, devices, groups.
 *
 * These are the settings a flat form cannot express, which is why they were
 * left out of the console entirely. They are not, however, all the same shape:
 * a local record has three fields and a client policy has eleven. A table would
 * have to be either eleven columns wide — unreadable, and horizontally
 * scrolling — or eleven tables.
 *
 * So an entry is a block, not a row: its fields are a label/control grid that
 * wraps at whatever width there is, and entries stack. Three fields read as one
 * line, eleven read as three, and neither needs a decision here about which
 * columns matter enough to show.
 *
 * The schema comes from the API (`api/settings.py`), like the flat form's, so
 * adding a field to a collection needs no change in this file.
 */
import { computed, ref, watch } from "vue";

interface Col {
  name: string; label: string; type: string;
  options: string[]; placeholder: string; help: string;
}
interface Spec {
  path: string; label: string; group: string; shape: string; scalar: boolean;
  columns: Col[]; help: string; key_label: string; restart: boolean;
}

const props = defineProps<{ spec: Spec; modelValue: any }>();
const emit = defineEmits<{ (e: "update:modelValue", v: any): void }>();

const isMap = computed(() => props.spec.shape === "map");

/** Entries as a uniform list of [key, value] so one template covers both
 *  shapes; a list's key is its index and is never shown.
 *
 * Held locally rather than derived from the prop on every keystroke. A prop
 * only changes after the parent has re-rendered, so two edits in the same tick
 * both started from the *pre-edit* value and the second overwrote the first —
 * filling in three fields of a new zone saved one of them. Editing the local
 * copy makes successive writes compose; the watcher takes the prop back over
 * whenever it genuinely differs, which is how a reload or a revert lands. */
const rows = ref<[string, any][]>([]);

const fromProp = (v: any): [string, any][] =>
  isMap.value
    ? Object.entries(v || {})
    : (v || []).map((x: any, i: number) => [String(i), x] as [string, any]);

const toProp = (list: [string, any][]) =>
  isMap.value ? Object.fromEntries(list) : list.map(([, v]) => v);

watch(() => props.modelValue, (v) => {
  if (JSON.stringify(toProp(rows.value)) !== JSON.stringify(v ?? (isMap.value ? {} : [])))
    rows.value = fromProp(v);
}, { immediate: true, deep: true });

const entries = computed<[string, any][]>(() => rows.value);

function commit(list: [string, any][]) {
  rows.value = list;
  emit("update:modelValue", toProp(list));
}

function blank() {
  if (props.spec.scalar) return props.spec.columns[0].type === "list" ? [] : "";
  const o: Record<string, any> = {};
  for (const c of props.spec.columns) {
    o[c.name] = c.type === "bool" ? false
      : c.type === "list" ? []
      : c.type === "int" ? 0
      : c.type === "tri" ? null
      : c.type === "select" ? (c.options[0] ?? "")
      : "";
  }
  return o;
}

const add = () => commit([...entries.value, [isMap.value ? "" : String(entries.value.length), blank()]]);
const remove = (i: number) => commit(entries.value.filter((_, n) => n !== i));

function setKey(i: number, key: string) {
  const list = entries.value.map((e, n) => (n === i ? [key, e[1]] : e) as [string, any]);
  commit(list);
}

function setField(i: number, name: string, value: any) {
  const list = entries.value.map((e, n) => {
    if (n !== i) return e;
    return [e[0], props.spec.scalar ? value : { ...(e[1] || {}), [name]: value }] as [string, any];
  });
  commit(list);
}

/** A list-valued cell is edited as one line per item, like every other list in
 *  this console — so the two never disagree about what a line means. */
const asText = (v: any) => (Array.isArray(v) ? v.join("\n") : (v ?? ""));
const fromText = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

/** Three states, three words. A checkbox cannot say "inherit", and rendering
 *  the inherited value as an unchecked box claims something false. */
const triValue = (v: any) => (v === null || v === undefined ? "inherit" : v ? "on" : "off");
const triSet = (s: string) => (s === "inherit" ? null : s === "on");
</script>

<template>
  <div class="col-set">
    <div class="col-head">
      <span class="st-lbl">
        {{ spec.label }}
        <em v-if="spec.help">{{ spec.help }}</em>
      </span>
      <span class="col-acts">
        <b v-if="spec.restart" title="saved now, applied on restart">restart</b>
        <span class="b-cap">{{ entries.length }}</span>
        <button type="button" class="btn" @click="add">add</button>
      </span>
    </div>

    <p class="col-empty" v-if="!entries.length">None configured.</p>

    <div class="col-item" v-for="([key, val], i) in entries" :key="i">
      <div class="col-grid">
        <label class="col-f" v-if="isMap">
          <span>{{ spec.key_label }}</span>
          <input type="text" :value="key" @input="setKey(i, ($event.target as HTMLInputElement).value)" />
        </label>

        <label class="col-f" v-for="c in spec.columns" :key="c.name"
               :class="{ wide: c.type === 'list' }" :title="c.help">
          <span>{{ c.label }}</span>

          <input v-if="c.type === 'bool'" type="checkbox" class="sw"
                 :checked="!!(spec.scalar ? val : val?.[c.name])"
                 @change="setField(i, c.name, ($event.target as HTMLInputElement).checked)" />

          <select v-else-if="c.type === 'tri'" :value="triValue(spec.scalar ? val : val?.[c.name])"
                  @change="setField(i, c.name, triSet(($event.target as HTMLSelectElement).value))">
            <option value="inherit">inherit</option>
            <option value="on">on</option>
            <option value="off">off</option>
          </select>

          <select v-else-if="c.type === 'select'" :value="spec.scalar ? val : val?.[c.name]"
                  @change="setField(i, c.name, ($event.target as HTMLSelectElement).value)">
            <option v-for="o in c.options" :key="o" :value="o">{{ o }}</option>
          </select>

          <textarea v-else-if="c.type === 'list'" rows="2" spellcheck="false"
                    :placeholder="c.placeholder"
                    :value="asText(spec.scalar ? val : val?.[c.name])"
                    @input="setField(i, c.name, fromText(($event.target as HTMLTextAreaElement).value))" />

          <input v-else-if="c.type === 'int'" type="number"
                 :value="spec.scalar ? val : val?.[c.name]"
                 @input="setField(i, c.name, Number(($event.target as HTMLInputElement).value))" />

          <input v-else type="text" :placeholder="c.placeholder"
                 :value="spec.scalar ? val : (val?.[c.name] ?? '')"
                 @input="setField(i, c.name, ($event.target as HTMLInputElement).value)" />
        </label>
      </div>

      <button type="button" class="btn col-rm" @click="remove(i)" title="remove this entry">
        remove
      </button>
    </div>
  </div>
</template>
