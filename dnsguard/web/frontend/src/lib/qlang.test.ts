/* qlang tests. Run with the bundled toolchain only:
 *
 *     node src/lib/qlang.test.ts
 *
 * Node strips the types itself, so a query language with real parsing logic
 * gets real tests without adding a test framework to a two-dependency app.
 */
import { compile, evaluate, explain, FIELDS, matcher, pushdown, QueryError, type Ctx, type Row } from "./qlang.ts";

let pass = 0;
const fails: string[] = [];

function ok(what: string, cond: boolean) {
  if (cond) pass++;
  else fails.push(what);
}

function eq(what: string, got: unknown, want: unknown) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) pass++;
  else fails.push(`${what}\n      got  ${g}\n      want ${w}`);
}

// ------------------------------------------------------------------ fixtures
const registrable = (n: string) => {
  const p = n.replace(/\.$/, "").toLowerCase().split(".");
  return p.slice(-2).join(".");
};
const ctx: Ctx = {
  registrable,
  clientsFor: (n) => (n.includes("shared") ? 4 : 1),
  firstSeen: (n) => (n.includes("novel") ? 1_000_000_000_000_000 - 60_000_000 : 1),
};

const row = (over: Partial<Row> = {}): Row => ({
  ts: 1_000_000_000_000_000,
  client_ip: "10.0.4.71",
  client_id: "lightbulb-3f2a",
  qname: "device-metrics.aws-iot.example.com",
  qtype: "A",
  proto: "udp",
  action: "blocked",
  reason: "list match",
  rule: "||aws-iot.example.com^",
  source: "hagezi-tif.medium",
  upstream: "",
  rcode: "NXDOMAIN",
  answers: "[]",
  elapsed_us: 412,
  ...over,
});

const m = (q: string, r: Row) => evaluate(compile(q), r, ctx);

// -------------------------------------------------------------------- basics
ok("empty query matches everything", m("", row()));
ok("bareword matches the name as a substring", m("aws-iot", row()));
ok("bareword misses when absent", !m("sonos", row()));
ok("bareword also searches the client id", m("lightbulb", row()));
ok("field match on name", m("name:aws-iot", row()));
ok("field match on client", m("client:10.0.4.71", row()));
ok("unrelated client does not match", !m("client:10.0.4.72", row()));

// ------------------------------------------------------------- outcome words
ok("outcome shorthand: blocked", m("blocked", row()));
ok("refused is a synonym for blocked", m("refused", row()));
ok("cached does not match a blocked row", !m("cached", row({ action: "blocked" })));
ok("cached matches a cached row", m("cached", row({ action: "cached" })));
ok("local matches authoritative", m("local", row({ action: "authoritative" })));

// -------------------------------------------------------------------- logic
ok("implicit and", m("blocked aws-iot", row()));
ok("implicit and fails if either side fails", !m("blocked sonos", row()));
ok("explicit and", m("blocked and aws-iot", row()));
ok("or, left true", m("cached or blocked", row()));
ok("or, both false", !m("cached or forwarded", row()));
ok("not", m("not cached", row()));
ok("bang prefix", m("!cached", row()));
ok("dash prefix", m("-cached", row()));
ok("parens bind tighter than juxtaposition", m("(cached or blocked) and aws-iot", row()));
ok("precedence: and binds tighter than or",
   m("cached and sonos or blocked", row()));
ok("not applies to the parenthesised group",
   !m("not (blocked or cached)", row()));

// -------------------------------------------------------------------- globs
ok("leading glob", m("name:*.aws-iot.example.com", row()));
ok("glob is anchored", !m("name:*.aws-iot.example.co", row()));
ok("question mark matches one character", m("client:10.0.4.7?", row()));
ok("plain value is a substring, not anchored", m("name:aws-iot.example", row()));
ok("exact operator is not a substring", !m("name=aws-iot", row()));
ok("exact operator matches the whole value",
   m("name=device-metrics.aws-iot.example.com", row()));
ok("not-equal operator", m("name!=sonos", row()));

// ------------------------------------------------------------------ numerics
ok("ms over", m("ms>0.4", row({ elapsed_us: 412 })));
ok("ms under", m("ms<1", row({ elapsed_us: 412 })));
ok("ms over, false", !m("ms>200", row({ elapsed_us: 412 })));
ok("slow flag", m("slow", row({ elapsed_us: 900_000 })));
ok("slow flag, false", !m("slow", row({ elapsed_us: 412 })));
ok("label count", m("labels>3", row()));
ok("label count boundary", !m("labels>4", row()));
ok("name length", m("len>20", row()));

// -------------------------------------------------------- computed and flags
ok("registrable field", m("reg:example.com", row()));
ok("tld field", m("tld:com", row()));
ok("tld field misses", !m("tld:net", row()));
ok("punycode flag", m("punycode", row({ qname: "xn--80ak6aa92e.com" })));
ok("punycode flag, false", !m("punycode", row()));
ok("nxdomain flag", m("nxdomain", row()));
ok("human flag needs a custom rule",
   m("human", row({ source: "custom", rule: "@@||example.com^" })));
ok("human flag is false for a list rule", !m("human", row()));
ok("clients uses the injected context", m("clients>2", row({ qname: "shared.example.com" })));
ok("clients is 1 by default", !m("clients>2", row()));
ok("novel flag uses first-seen", m("novel", row({ qname: "novel.example.com" })));
ok("novel flag is false for an old name", !m("novel", row()));
ok("age in days", m("age>1000", row()));

// ------------------------------------------------------------------- quoting
ok("quoted value keeps spaces", m('reason:"list match"', row()));
ok("a quoted outcome word is a plain search, not a shorthand",
   !m('"cached"', row()));
ok("quoted string can hold a colon",
   m('rule:"||aws-iot.example.com^"', row({ rule: "||aws-iot.example.com^" })));

// ------------------------------------------------------------------- errors
function throws(q: string): boolean {
  try { compile(q); return false; } catch (e) { return e instanceof QueryError; }
}
ok("unknown field is an error", throws("nope:1"));
ok("missing paren is an error", throws("(blocked"));
ok("dangling operator is an error", throws("client:"));
ok("unterminated string is an error", throws('name:"abc'));
ok("trailing paren is an error", throws("blocked)"));

// ----------------------------------------------------------------- pushdown
eq("equality on an indexed column is pushed down",
   pushdown(compile("client:10.0.4.71")), { client: "10.0.4.71" });
eq("several conjoined equalities are all pushed down",
   pushdown(compile("client:10.0.4.71 and blocked")),
   { client: "10.0.4.71", action: "blocked" });
eq("or is never pushed down", pushdown(compile("cached or blocked")), {});
eq("a negated term is not pushed down", pushdown(compile("not cached")), {});
eq("computed fields have no server equivalent", pushdown(compile("reg:example.com")), {});
eq("numeric comparisons are not pushed down", pushdown(compile("ms>200")), {});
eq("a glob on the name keeps its literal core, which the server matches as a substring",
   pushdown(compile("name:*.aws-iot.example.com")), { qname: ".aws-iot.example.com" });
eq("an interior glob cannot be pushed down",
   pushdown(compile("name:a*b.example.com")), {});
eq("contradictory equalities keep the first, which is a safe superset",
   pushdown(compile("client:10.0.0.1 and client:10.0.0.2")), { client: "10.0.0.1" });
{
  // …and the contradiction still yields nothing once the client filters
  const ast = compile("client:10.0.0.1 and client:10.0.0.2");
  ok("a contradiction matches no row despite the pushdown",
     !evaluate(ast, row({ client_ip: "10.0.0.1" }), ctx));
}
eq("mixed expression pushes down only its conjoined part",
   pushdown(compile("client:10.0.4.71 and (cached or blocked)")), { client: "10.0.4.71" });

// pushdown must never change the result — only how much is fetched
{
  const rows = [
    row(), row({ action: "cached", qname: "a.example.com" }),
    row({ client_ip: "10.0.4.99", action: "forwarded" }),
    row({ qname: "xn--e1afmkfd.example.com", action: "failed", elapsed_us: 900_000 }),
  ];
  for (const q of ["client:10.0.4.71 and blocked", "cached or failed", "not cached",
                   "name:*.example.com and ms<1000", "slow or punycode"]) {
    const ast = compile(q);
    const direct = rows.filter((r) => evaluate(ast, r, ctx));
    // simulate the server applying the pushed-down params, then re-filtering
    const pd = pushdown(ast);
    const served = rows.filter((r) =>
      (!pd.client || r.client_ip === pd.client) &&
      (!pd.action || r.action === pd.action) &&
      (!pd.qname || r.qname.includes(pd.qname)));
    const viaServer = served.filter((r) => evaluate(ast, r, ctx));
    eq(`pushdown preserves the result set for: ${q}`, viaServer, direct);
  }
}

// ------------------------------------------------------------------ explain
eq("explain reads back as a sentence, not as a field reference",
   explain(compile("blocked")), "The outcome contains blocked.");
eq("explain uses the noun form for an exact match",
   explain(compile("client=10.0.0.1")), "The device address is 10.0.0.1.");
eq("explain names a glob as a match",
   explain(compile("name:*.example.com")), "The name matches *.example.com.");
ok("explain joins with and", explain(compile("blocked and client:10.0.0.1")).includes(" and "));
ok("explain names a numeric comparison", explain(compile("ms>200")).includes("over 200"));
ok("every field has a sentence form", Object.values(FIELDS).every((f) => !!f.noun));
ok("explain ends in a full stop", explain(compile("cached")).endsWith("."));
eq("explain an empty query", explain(compile("")), "Everything.");

// ------------------------------------------------------------------ matcher
{
  const f = matcher("blocked and reg:example.com", ctx);
  ok("matcher accepts a matching row", f(row()));
  ok("matcher rejects a non-matching row", !f(row({ action: "cached" })));
}

// -------------------------------------------------------------------- report
if (fails.length) {
  console.error(`\nqlang: ${pass} passed, ${fails.length} FAILED\n`);
  for (const f of fails) console.error("  ✗ " + f);
  process.exit(1);
}
console.log(`qlang: ${pass} assertions passed`);
