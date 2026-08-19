/* Faceted aggregation — the engine behind the column browser.
 *
 * The organising idea: a DNS console is a browser over one relation (query log
 * rows) and the interesting question is always "grouped by what, then by what".
 * So the interface is a chain of facets, the operator chooses the order, and
 * each column is one level of that chain. Choosing `tld → domain → name` reads
 * the namespace; choosing `device → domain` reads the network; choosing
 * `rule → name` reads your own policy back to you. Same mechanism, three
 * different questions, no separate screens.
 *
 * Nothing here knows about pixels. It is all pure so the part with judgement in
 * it — what counts as a level, what a node summarises, how novelty is decided —
 * can be tested without a browser.
 */
import { registrable } from "./dnsname.ts";
import { isAuthored, isStale, kindOf, type Kind } from "./outcome.ts";
import type { Row } from "./qlang.ts";

export type FacetKey =
  | "tld" | "domain" | "name" | "device" | "qtype" | "upstream" | "rule" | "source";

export interface FacetDef {
  key: FacetKey;
  /** column heading */
  label: string;
  /** one line explaining what a row in this column is */
  of: string;
  /** the value a row contributes; "" means the row does not belong in this facet */
  value: (r: Row) => string;
  /** render the value as an identifier (mono) rather than as interface text */
  ident: boolean;
  /** qlang expression that isolates one value, so a selection is expressible */
  express: (v: string) => string;
}

const clean = (n: string) => n.replace(/\.$/, "").toLowerCase();

export const FACETS: Record<FacetKey, FacetDef> = {
  tld: {
    key: "tld", label: "Suffix", of: "top-level domain", ident: true,
    value: (r) => clean(r.qname).split(".").pop() || "",
    express: (v) => `tld=${v}`,
  },
  domain: {
    key: "domain", label: "Domain", of: "what somebody owns",
    ident: true,
    value: (r) => registrable(r.qname),
    express: (v) => `reg=${v}`,
  },
  name: {
    key: "name", label: "Name", of: "the exact name asked for", ident: true,
    value: (r) => clean(r.qname),
    express: (v) => `name=${v}`,
  },
  device: {
    key: "device", label: "Device", of: "the client that asked", ident: true,
    value: (r) => r.client_ip || "",
    express: (v) => `client=${v}`,
  },
  qtype: {
    key: "qtype", label: "Type", of: "record type requested", ident: true,
    value: (r) => (r.qtype || "").toUpperCase(),
    express: (v) => `type=${v}`,
  },
  upstream: {
    key: "upstream", label: "Resolver", of: "which upstream answered", ident: true,
    value: (r) => r.upstream || "",
    express: (v) => `upstream=${v}`,
  },
  rule: {
    key: "rule", label: "Rule", of: "the rule that decided it", ident: true,
    value: (r) => r.rule || "",
    express: (v) => `rule=${v}`,
  },
  source: {
    key: "source", label: "List", of: "where the deciding rule came from", ident: false,
    value: (r) => r.source || "",
    express: (v) => `source=${v}`,
  },
};

/** Facet orders worth offering, and what each one is for. */
export const PLANS: { name: string; note: string; keys: FacetKey[] }[] = [
  { name: "Namespace", note: "what the network asks for", keys: ["tld", "domain", "name"] },
  { name: "Devices", note: "who is asking, and for what", keys: ["device", "domain", "name"] },
  { name: "Policy", note: "your rules, read back by effect", keys: ["source", "rule", "name"] },
  { name: "Resolution", note: "where answers come from", keys: ["upstream", "domain", "name"] },
];

export interface Node {
  value: string;
  total: number;
  /** counts per outcome, in KINDS order */
  by: Record<Kind, number>;
  devices: number;
  names: number;
  stale: number;
  authored: number;
  firstTs: number;
  lastTs: number;
  /** 95th percentile time to answer, milliseconds; 0 when nothing travelled */
  p95: number;
  /** rows in this node, kept so a leaf can hand one straight to the evidence panel */
  rows: Row[];
}

const EMPTY_BY = (): Record<Kind, number> => ({
  cache: 0, upstream: 0, local: 0, blocked: 0, failed: 0, unknown: 0,
});

function percentile(sorted: number[], q: number): number {
  if (!sorted.length) return 0;
  const i = Math.min(sorted.length - 1, Math.floor(sorted.length * q));
  return Math.round(sorted[i] / 100) / 10;   // µs -> ms, one decimal
}

/** Group rows by one facet and summarise each group. */
export function aggregate(rows: Row[], key: FacetKey): Node[] {
  const def = FACETS[key];
  const buckets = new Map<string, Row[]>();
  for (const r of rows) {
    const v = def.value(r);
    if (!v) continue;                     // a facet a row has no value for is not a bucket
    const b = buckets.get(v);
    if (b) b.push(r); else buckets.set(v, [r]);
  }
  const out: Node[] = [];
  for (const [value, rs] of buckets) {
    const by = EMPTY_BY();
    const devices = new Set<string>();
    const names = new Set<string>();
    let stale = 0, authored = 0, firstTs = Infinity, lastTs = 0;
    const lat: number[] = [];
    for (const r of rs) {
      by[kindOf(r)]++;
      devices.add(r.client_ip);
      names.add(clean(r.qname));
      if (isStale(r)) stale++;
      if (isAuthored(r)) authored++;
      if (r.ts < firstTs) firstTs = r.ts;
      if (r.ts > lastTs) lastTs = r.ts;
      if (r.elapsed_us) lat.push(r.elapsed_us);
    }
    lat.sort((a, b) => a - b);
    out.push({
      value, total: rs.length, by, devices: devices.size, names: names.size,
      stale, authored, firstTs: firstTs === Infinity ? 0 : firstTs, lastTs,
      p95: percentile(lat, 0.95), rows: rs,
    });
  }
  return out;
}

export type SortKey = "volume" | "blocked" | "failed" | "recent" | "slowest" | "name";

/**
 * Sort a column. Volume is the default because it answers "what dominates";
 * the others exist because the interesting node is often not the biggest one —
 * a name asked twice that failed both times matters more than a million cache
 * hits, and a volume sort buries it forever.
 */
export function sortNodes(nodes: Node[], by: SortKey): Node[] {
  const n = nodes.slice();
  switch (by) {
    case "blocked": return n.sort((a, b) => b.by.blocked - a.by.blocked || b.total - a.total);
    case "failed": return n.sort((a, b) => (b.by.failed + b.stale) - (a.by.failed + a.stale) || b.total - a.total);
    case "recent": return n.sort((a, b) => b.lastTs - a.lastTs);
    case "slowest": return n.sort((a, b) => b.p95 - a.p95 || b.total - a.total);
    case "name": return n.sort((a, b) => a.value.localeCompare(b.value));
    default: return n.sort((a, b) => b.total - a.total || a.value.localeCompare(b.value));
  }
}

export const SORTS: { key: SortKey; label: string; of: string }[] = [
  { key: "volume", label: "Volume", of: "what dominates the traffic" },
  { key: "blocked", label: "Blocked", of: "what policy is stopping most" },
  { key: "failed", label: "Trouble", of: "what failed or went stale" },
  { key: "slowest", label: "Slowest", of: "what costs the most time" },
  { key: "recent", label: "Newest", of: "what was asked most recently" },
  { key: "name", label: "A–Z", of: "alphabetical, for looking something up" },
];

/**
 * Rows matching every level that has been picked.
 *
 * Levels without a pick are skipped, not treated as the end of the chain. In a
 * column browser it is entirely normal to reach past the first column — you see
 * a domain you recognise in the second column and click it without caring which
 * suffix it sits under — and stopping at the first gap silently ignores that
 * click. It looked like a rendering bug and was this line.
 */
export function narrow(rows: Row[], plan: FacetKey[], picked: (string | null)[]): Row[] {
  let out = rows;
  for (let i = 0; i < plan.length; i++) {
    const v = picked[i];
    if (!v) continue;
    const def = FACETS[plan[i]];
    out = out.filter((r) => def.value(r) === v);
  }
  return out;
}

/**
 * Which single column a screen too narrow for the chain should be showing.
 *
 * On a wide screen every level is on the page at once and the operator's
 * position in the chain is implicit in what is highlighted. One column wide
 * there is nowhere to put that, so the position has to be derived: it is one
 * past the deepest level that has a pick.
 *
 * Deepest rather than first-unpicked, because picks are allowed to skip a
 * level — narrow() reaches past a gap on purpose, and a restored permalink can
 * arrive with one. First-unpicked would send a shared link back to the top.
 *
 * Returning plan.length means every level is decided and there is no column
 * left to draw: that is the evidence panel's turn on the screen.
 */
export function stage(plan: FacetKey[], picked: (string | null)[]): number {
  let deepest = -1;
  for (let i = 0; i < plan.length; i++) if (picked[i]) deepest = i;
  return Math.min(deepest + 1, plan.length);
}

/** The selection expressed as a qlang query, so any view of it is shareable. */
export function asQuery(plan: FacetKey[], picked: (string | null)[]): string {
  const parts: string[] = [];
  for (let i = 0; i < plan.length; i++) {
    const v = picked[i];
    if (!v) continue;          // same reasoning as narrow(): skip, do not stop
    parts.push(FACETS[plan[i]].express(v));
  }
  return parts.join(" and ");
}

/** Totals for a set of rows — the numbers a header states about a selection. */
export interface Summary {
  total: number; by: Record<Kind, number>; devices: number; names: number;
  stale: number; authored: number; p50: number; p95: number; p99: number;
  from: number; to: number;
}

export function summarise(rows: Row[]): Summary {
  const by = EMPTY_BY();
  const devices = new Set<string>(), names = new Set<string>();
  let stale = 0, authored = 0, from = Infinity, to = 0;
  const lat: number[] = [];
  for (const r of rows) {
    by[kindOf(r)]++;
    devices.add(r.client_ip);
    names.add(clean(r.qname));
    if (isStale(r)) stale++;
    if (isAuthored(r)) authored++;
    if (r.ts < from) from = r.ts;
    if (r.ts > to) to = r.ts;
    if (r.elapsed_us) lat.push(r.elapsed_us);
  }
  lat.sort((a, b) => a - b);
  return {
    total: rows.length, by, devices: devices.size, names: names.size, stale, authored,
    p50: percentile(lat, 0.5), p95: percentile(lat, 0.95), p99: percentile(lat, 0.99),
    from: from === Infinity ? 0 : from, to,
  };
}

/**
 * Activity over time for a selection, bucketed for the span band.
 *
 * Answered and blocked are returned separately rather than summed, because the
 * shape of the two against a shared baseline is the whole point: a device whose
 * refusals rise while its answers stay flat is retrying, and a device where both
 * fall together has simply gone quiet.
 *
 * Answers are further split into what cost a round trip and what did not, which
 * turns the band into a reading of the cache as well as of the traffic: a
 * healthy resolver is mostly the quiet fill, and a cache that stops working
 * shows up as the mid fill swallowing the band without the total changing.
 */
export interface Bucket {
  t: number;
  /** answered without leaving the box — cache and local authority */
  free: number;
  /** answered, but it cost a round trip */
  travelled: number;
  blocked: number;
  failed: number;
}

export function histogram(rows: Row[], t0: number, t1: number, buckets = 96): Bucket[] {
  const span = Math.max(1, t1 - t0);
  const step = span / buckets;
  const out: Bucket[] = Array.from({ length: buckets }, (_, i) => ({
    t: t0 + i * step, free: 0, travelled: 0, blocked: 0, failed: 0,
  }));
  for (const r of rows) {
    const i = Math.floor(((r.ts - t0) / span) * buckets);
    if (i < 0 || i >= buckets) continue;
    const k = kindOf(r);
    if (k === "blocked") out[i].blocked++;
    else if (k === "failed") out[i].failed++;
    else if (k === "upstream") out[i].travelled++;
    else out[i].free++;      // cache and local: answered at no network cost
  }
  return out;
}
