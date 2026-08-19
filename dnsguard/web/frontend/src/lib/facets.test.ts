/* Facet + outcome tests.  node src/lib/facets.test.ts */
import { registrable, align, shape, classifyAddr, answerList } from "./dnsname.ts";
import { kindOf, isStale, isAuthored, KINDS } from "./outcome.ts";
import {
  aggregate, asQuery, FACETS, histogram, narrow, sortNodes, stage, summarise,
} from "./facets.ts";
import type { Row } from "./qlang.ts";

let pass = 0;
const fails: string[] = [];
const ok = (w: string, c: boolean) => { c ? pass++ : fails.push(w); };
const eq = (w: string, g: unknown, e: unknown) => {
  const a = JSON.stringify(g), b = JSON.stringify(e);
  a === b ? pass++ : fails.push(`${w}\n      got  ${a}\n      want ${b}`);
};

const T = 1_700_000_000_000_000;
const row = (o: Partial<Row> = {}): Row => ({
  ts: T, client_ip: "10.0.0.1", qname: "a.example.com", qtype: "A",
  action: "forwarded", rcode: "NOERROR", elapsed_us: 20_000, ...o,
});

// ------------------------------------------------------------ outcome kinds
eq("forwarded travels upstream", kindOf(row()), "upstream");
eq("cached", kindOf(row({ action: "cached" })), "cache");
eq("authoritative is local", kindOf(row({ action: "authoritative" })), "local");
eq("a rewrite is answered locally", kindOf(row({ action: "rewrite" })), "local");
eq("blocked is blocked", kindOf(row({ action: "blocked" })), "blocked");
eq("refused is blocked", kindOf(row({ action: "refused" })), "blocked");
eq("safe search is blocked", kindOf(row({ action: "safesearch" })), "blocked");
eq("rate limited is blocked", kindOf(row({ action: "ratelimited" })), "blocked");
eq("failed", kindOf(row({ action: "failed" })), "failed");
eq("servfail outranks the recorded action",
   kindOf(row({ action: "forwarded", rcode: "SERVFAIL" })), "failed");
eq("a missing action stays unknown rather than being folded in",
   kindOf(row({ action: "" })), "unknown");
// Blocked leads every legend and every ordered list in the console: it is what
// someone opened the page to find. Cost order came second and cost nothing.
eq("six kinds, what you came to look for first", KINDS,
   ["blocked", "failed", "cache", "upstream", "local", "unknown"]);

ok("a stale cache hit is flagged", isStale(row({ action: "cached", reason: "stale-fallback" })));
ok("a fresh cache hit is not", !isStale(row({ action: "cached" })));
ok("stale only applies to cache hits",
   !isStale(row({ action: "forwarded", reason: "stale-fallback" })));
ok("a custom rule is authored", isAuthored(row({ source: "custom", rule: "@@||x^" })));
ok("a list rule is not", !isAuthored(row({ source: "hagezi", rule: "||x^" })));
ok("custom with no rule is not", !isAuthored(row({ source: "custom" })));

// ------------------------------------------------------------- facet values
eq("suffix facet", FACETS.tld.value(row({ qname: "a.example.co.uk" })), "uk");
eq("domain facet uses the registrable boundary",
   FACETS.domain.value(row({ qname: "a.b.example.co.uk" })), "example.co.uk");
eq("name facet is the exact name, normalised",
   FACETS.name.value(row({ qname: "A.Example.COM." })), "a.example.com");
eq("device facet", FACETS.device.value(row()), "10.0.0.1");
eq("type facet is upper case", FACETS.qtype.value(row({ qtype: "aaaa" })), "AAAA");
eq("a row with no upstream contributes nothing to that facet",
   FACETS.upstream.value(row({ upstream: "" })), "");

// ------------------------------------------------------------- aggregation
{
  const rows = [
    row({ qname: "a.example.com", action: "cached" }),
    row({ qname: "b.example.com", action: "blocked", client_ip: "10.0.0.2" }),
    row({ qname: "c.other.net", action: "failed", elapsed_us: 900_000 }),
    row({ qname: "d.example.com", action: "cached", reason: "stale-fallback" }),
    row({ qname: "e.example.com", action: "blocked", source: "custom", rule: "||e^" }),
  ];
  const nodes = aggregate(rows, "domain");
  eq("one node per distinct value", nodes.length, 2);
  const ex = nodes.find((n) => n.value === "example.com")!;
  eq("node total", ex.total, 4);
  eq("outcome split is kept per node", [ex.by.cache, ex.by.blocked], [2, 2]);
  eq("distinct devices counted", ex.devices, 2);
  eq("distinct names counted", ex.names, 4);
  eq("stale counted", ex.stale, 1);
  eq("authored counted", ex.authored, 1);
  ok("first and last timestamps recorded", ex.firstTs > 0 && ex.lastTs >= ex.firstTs);
  const other = nodes.find((n) => n.value === "other.net")!;
  ok("p95 is in milliseconds", other.p95 > 800 && other.p95 < 1000);
  eq("rows travel with the node so a leaf needs no second pass", other.rows.length, 1);
}

{
  // a facet a row has no value for must not become an empty bucket
  const nodes = aggregate([row({ upstream: "" }), row({ upstream: "tls://9.9.9.9" })], "upstream");
  eq("rows lacking the facet are skipped", nodes.length, 1);
  eq("the surviving node is the one with a value", nodes[0].value, "tls://9.9.9.9");
}
eq("aggregating nothing yields nothing", aggregate([], "domain"), []);

// ------------------------------------------------------------------ sorting
{
  const rows = [
    ...Array.from({ length: 9 }, () => row({ qname: "big.example.com" })),
    row({ qname: "small.test.net", action: "blocked" }),
    row({ qname: "small.test.net", action: "blocked" }),
    row({ qname: "slow.late.org", elapsed_us: 3_000_000, ts: T + 90 }),
  ];
  const nodes = aggregate(rows, "domain");
  eq("volume sort puts the biggest first", sortNodes(nodes, "volume")[0].value, "example.com");
  eq("blocked sort surfaces what policy stops most",
     sortNodes(nodes, "blocked")[0].value, "test.net");
  eq("slowest sort surfaces cost, not size",
     sortNodes(nodes, "slowest")[0].value, "late.org");
  eq("recent sort uses the last sighting",
     sortNodes(nodes, "recent")[0].value, "late.org");
  eq("alphabetical", sortNodes(nodes, "name").map((n) => n.value),
     ["example.com", "late.org", "test.net"]);
  ok("sorting does not mutate the input",
     JSON.stringify(nodes.map((n) => n.value)) !== "" && nodes.length === 3);
}

// ------------------------------------------------------------------- narrow
{
  const rows = [
    row({ qname: "a.example.com", client_ip: "10.0.0.1" }),
    row({ qname: "b.example.com", client_ip: "10.0.0.2" }),
    row({ qname: "c.other.net", client_ip: "10.0.0.1" }),
  ];
  const plan = ["domain", "device", "name"] as const;
  eq("no selection narrows nothing", narrow(rows, [...plan], [null, null, null]).length, 3);
  eq("first level", narrow(rows, [...plan], ["example.com", null, null]).length, 2);
  eq("two levels", narrow(rows, [...plan], ["example.com", "10.0.0.1", null]).length, 1);
  eq("a pick at a deeper level applies even with the level above unpicked",
     narrow(rows, [...plan], [null, "10.0.0.1", null]).length, 2);
  eq("picks at two non-adjacent levels both apply",
     narrow(rows, [...plan], ["other.net", null, "c.other.net"]).length, 1);
  eq("a selection that matches nothing yields nothing",
     narrow(rows, [...plan], ["nope.example", null, null]).length, 0);
}

// --------------------------------------------------------------- stage
// One column wide, the position in the chain has to be derived from the picks.
eq("nothing picked starts at the first level", stage(["tld", "domain", "name"], [null, null, null]), 0);
eq("one pick steps to the second level",
   stage(["tld", "domain", "name"], ["com", null, null]), 1);
eq("two picks step to the third",
   stage(["tld", "domain", "name"], ["com", "example.com", null]), 2);
eq("every level picked leaves no column to draw",
   stage(["tld", "domain", "name"], ["com", "example.com", "a.example.com"]), 3);
// a shared link can arrive with a gap in it; it must not be sent back to the top
eq("a skipped level does not reset the position",
   stage(["tld", "domain", "name"], [null, "example.com", null]), 2);
eq("the deepest pick wins even with a gap before it",
   stage(["tld", "domain", "name"], ["com", null, "a.example.com"]), 3);
eq("a shorter picked array is not an error", stage(["tld", "domain"], []), 0);

eq("a selection is expressible as a query",
   asQuery(["domain", "device", "name"], ["example.com", "10.0.0.1", null]),
   "reg=example.com and client=10.0.0.1");
eq("an empty selection is an empty query",
   asQuery(["domain"], [null]), "");
eq("a query skips unpicked levels rather than stopping at them",
   asQuery(["tld", "domain", "name"], [null, "example.com", null]), "reg=example.com");
{
  // every facet's expression must be a query qlang can actually parse
  const { compile } = await import("./qlang.ts");
  for (const f of Object.values(FACETS)) {
    try { compile(f.express("x.example.com")); pass++; }
    catch { fails.push(`facet ${f.key} produces an unparseable query`); }
  }
}

// ------------------------------------------------------------------ summary
{
  const s = summarise([
    row({ action: "cached" }), row({ action: "blocked", client_ip: "10.0.0.9" }),
    row({ action: "forwarded", elapsed_us: 100_000 }), row({ action: "failed" }),
  ]);
  eq("summary total", s.total, 4);
  eq("summary counts by kind", [s.by.cache, s.by.blocked, s.by.failed], [1, 1, 1]);
  eq("summary devices", s.devices, 2);
  ok("summary percentiles ordered", s.p50 <= s.p95 && s.p95 <= s.p99);
  ok("summary spans the rows", s.from > 0 && s.to >= s.from);
  eq("summarising nothing is all zeroes", summarise([]).total, 0);
}

// ---------------------------------------------------------------- histogram
{
  // answers are split by whether they cost a round trip, so the band can read
  // the cache as well as the traffic
  const t0 = T;
  const split = histogram([
    row({ ts: t0, action: "cached" }), row({ ts: t0, action: "authoritative" }),
    row({ ts: t0, action: "forwarded" }),
  ], t0, t0 + 1000, 1);
  eq("cache and local are free; forwarded travelled",
     [split[0].free, split[0].travelled], [2, 1]);
}
{
  const t0 = T, t1 = T + 1_000_000;
  const h = histogram([
    row({ ts: t0 + 10 }), row({ ts: t0 + 10, action: "blocked" }),
    row({ ts: t1 - 10, action: "failed" }),
    row({ ts: t1 + 5_000_000 }),                    // outside the window
  ], t0, t1, 4);
  eq("bucket count", h.length, 4);
  eq("answered and blocked are kept apart", [h[0].travelled, h[0].blocked], [1, 1]);
  eq("failures are their own series", h[3].failed, 1);
  eq("rows outside the window are dropped",
     h.reduce((n, b) => n + b.free + b.travelled + b.blocked + b.failed, 0), 3);
  ok("bucket timestamps ascend", h[1].t > h[0].t);
}

// -------------------------------------------------- name helpers still hold
eq("registrable", registrable("x.y.example.co.uk"), "example.co.uk");
eq("align", align("a.b.example.com"), { sub: "a.b", reg: "example.com" });
ok("entropy flags a random label", shape("kq3v9z7x1p2w.example.com").entropy > 3);
eq("address classes", classifyAddr("10.0.0.1"), "private");
eq("answers parse", answerList('["1.2.3.4"]'), ["1.2.3.4"]);

if (fails.length) {
  console.error(`\nfacets: ${pass} passed, ${fails.length} FAILED\n`);
  for (const f of fails) console.error("  ✗ " + f);
  process.exit(1);
}
console.log(`facets: ${pass} assertions passed`);
