/* qlang — the query language for the Field.
 *
 * A filter box that only does substring matching forces the operator to think
 * in one dimension at a time. DNS questions are not one-dimensional: "what did
 * the IoT group ask for, that was refused, that is not on a list I wrote" is a
 * single thought and should be a single expression.
 *
 *   client:10.0.4.71 and refused
 *   name:*.aws-iot.example.com and not cached
 *   (blocked or failed) and ms>200
 *   reg:doubleclick.net and clients>1
 *   tld:zip or punycode
 *
 * Grammar (recursive descent, no dependencies):
 *
 *   expr    := or
 *   or      := and (("or" | "|") and)*
 *   and     := unary (("and" | "&")? unary)*        -- juxtaposition means AND
 *   unary   := ("not" | "!" | "-") unary | primary
 *   primary := "(" expr ")" | term
 *   term    := field (":"|"="|"!="|">"|"<"|">="|"<=") value | bareword
 *   value   := '"' … '"' | bare (globs: * ?)
 *
 * Two things make it worth having rather than a regex box:
 *
 *   * `pushdown()` extracts the part of an expression the server can answer
 *     (equality on indexed columns, time bounds) so the client fetches rows it
 *     will actually keep. The remainder is evaluated locally. Nothing is
 *     silently dropped: whatever cannot be pushed down is still applied.
 *   * `explain()` renders the parsed expression back as an English sentence.
 *     The most common failure with a query DSL is an expression that does
 *     something other than what its author believed, and the cheapest defence
 *     is to read it back to them.
 */

// ---------------------------------------------------------------- row shape
/** One persisted query-log row, as the API returns it. */
export interface Row {
  ts: number;            // microseconds
  client_ip: string;
  client_id?: string;
  qname: string;
  qtype: string;
  proto?: string;
  action: string;
  reason?: string;
  rule?: string;
  source?: string;
  upstream?: string;
  rcode: string;
  answers?: string;      // JSON array as text
  elapsed_us?: number;
}

// ---------------------------------------------------------------- tokenizer
type Tok =
  | { k: "word"; v: string; quoted: boolean }
  | { k: "op"; v: string }
  | { k: "lparen" }
  | { k: "rparen" }
  | { k: "eof" };

const OPS = [">=", "<=", "!=", ":", "=", ">", "<"];

export class QueryError extends Error {
  // written out longhand rather than as a parameter property: this module is
  // run directly by `node src/lib/qlang.test.ts`, which strips types without
  // transforming them, and a parameter property is a transform.
  at: number;
  constructor(message: string, at: number) {
    super(message);
    this.at = at;
  }
}

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === " " || c === "\t" || c === "\n") { i++; continue; }
    if (c === "(") { out.push({ k: "lparen" }); i++; continue; }
    if (c === ")") { out.push({ k: "rparen" }); i++; continue; }
    if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1, v = "";
      while (j < src.length && src[j] !== quote) {
        if (src[j] === "\\" && j + 1 < src.length) { v += src[j + 1]; j += 2; continue; }
        v += src[j++];
      }
      if (j >= src.length) throw new QueryError("unterminated string", i);
      out.push({ k: "word", v, quoted: true });
      i = j + 1;
      continue;
    }
    const op = OPS.find((o) => src.startsWith(o, i));
    if (op) { out.push({ k: "op", v: op }); i += op.length; continue; }
    // a bareword runs to whitespace, a paren, or an operator
    let j = i;
    while (j < src.length && !" \t\n()".includes(src[j]) && !OPS.some((o) => src.startsWith(o, j))) j++;
    out.push({ k: "word", v: src.slice(i, j), quoted: false });
    i = j;
  }
  out.push({ k: "eof" });
  return out;
}

// ------------------------------------------------------------------- fields
type Kind = "text" | "num" | "flag";

interface FieldDef {
  kind: Kind;
  /** value pulled off a row; numbers for "num", string for "text" */
  get: (r: Row, ctx: Ctx) => string | number | undefined;
  /** server-side query parameter, when equality on this field can be pushed down */
  param?: string;
  /** full description, for the reference table */
  help: string;
  /**
   * Short noun phrase used when a query is read back as a sentence.
   *
   * Separate from `help` deliberately: `help` may enumerate values ("outcome:
   * blocked, cached, forwarded…"), which is right in a reference and unreadable
   * in a sentence. Before this existed, `blocked` explained itself as "Outcome:
   * blocked, cached, forwarded… containing blocked."
   */
  noun: string;
}

/** Extra facts the evaluator may need that are not on the row itself. */
export interface Ctx {
  /** registrable domain (eTLD+1) for a name — injected so qlang stays pure */
  registrable: (name: string) => string;
  /** how many distinct clients asked this name in the loaded window */
  clientsFor?: (name: string) => number;
  /** epoch microseconds when this network first ever asked this name */
  firstSeen?: (name: string) => number | undefined;
}

const lower = (v: string | undefined) => (v || "").toLowerCase();

export const FIELDS: Record<string, FieldDef> = {
  name: { kind: "text", get: (r) => lower(r.qname), param: "qname", help: "queried name", noun: "the name" },
  reg: { kind: "text", get: (r, c) => c.registrable(r.qname), help: "registrable domain (eTLD+1)", noun: "the registrable domain" },
  tld: { kind: "text", get: (r) => lower(r.qname).replace(/\.$/, "").split(".").pop() || "", help: "top-level domain", noun: "the suffix" },
  client: { kind: "text", get: (r) => lower(r.client_ip), param: "client", help: "client address", noun: "the device address" },
  id: { kind: "text", get: (r) => lower(r.client_id), help: "client identity label", noun: "the device name" },
  action: { kind: "text", get: (r) => lower(r.action), param: "action", help: "outcome: blocked, cached, forwarded, failed, authoritative…", noun: "the outcome" },
  rcode: { kind: "text", get: (r) => lower(r.rcode), param: "rcode", help: "response code", noun: "the response code" },
  upstream: { kind: "text", get: (r) => lower(r.upstream), param: "upstream", help: "resolver that answered", noun: "the upstream" },
  type: { kind: "text", get: (r) => lower(r.qtype), help: "query type: a, aaaa, https…", noun: "the record type" },
  proto: { kind: "text", get: (r) => lower(r.proto), help: "client transport", noun: "the transport" },
  rule: { kind: "text", get: (r) => lower(r.rule), help: "rule that decided it", noun: "the deciding rule" },
  source: { kind: "text", get: (r) => lower(r.source), help: "list or subsystem the rule came from", noun: "the rule's source" },
  reason: { kind: "text", get: (r) => lower(r.reason), help: "decision note", noun: "the decision note" },
  answer: { kind: "text", get: (r) => lower(r.answers), help: "text of the answer records", noun: "the answer records" },
  ms: { kind: "num", get: (r) => (r.elapsed_us || 0) / 1000, help: "time to answer, milliseconds", noun: "the time to answer, in milliseconds" },
  labels: { kind: "num", get: (r) => lower(r.qname).replace(/\.$/, "").split(".").length, help: "label count in the name", noun: "the label count" },
  len: { kind: "num", get: (r) => r.qname.replace(/\.$/, "").length, help: "name length in characters", noun: "the name length" },
  clients: { kind: "num", get: (r, c) => (c.clientsFor ? c.clientsFor(lower(r.qname)) : 1), help: "distinct clients asking this name in view", noun: "the number of devices asking it" },
  age: {
    kind: "num",
    get: (r, c) => {
      const fs = c.firstSeen?.(lower(r.qname));
      return fs === undefined ? undefined : (r.ts - fs) / 86_400_000_000;
    },
    help: "days between this network first asking the name and this query",
    noun: "the days since this name was first seen",
  },
};

/** Barewords that are outcome shorthands rather than substring searches. */
const ACTION_WORDS: Record<string, string> = {
  blocked: "blocked", refused: "blocked", cached: "cached", forwarded: "forwarded",
  failed: "failed", local: "authoritative", authoritative: "authoritative",
  rewrite: "rewrite", safesearch: "safesearch", ratelimited: "ratelimited",
};

/** Barewords that are computed predicates with no field of their own. */
const FLAGS: Record<string, { test: (r: Row, c: Ctx) => boolean; help: string }> = {
  punycode: { test: (r) => lower(r.qname).includes("xn--"), help: "name uses punycode" },
  nxdomain: { test: (r) => lower(r.rcode) === "nxdomain", help: "answer was NXDOMAIN" },
  slow: { test: (r) => (r.elapsed_us || 0) > 200_000, help: "took over 200ms" },
  human: { test: (r) => !!r.rule && lower(r.source) === "custom", help: "decided by a rule a person wrote" },
  novel: {
    test: (r, c) => {
      const fs = c.firstSeen?.(lower(r.qname));
      return fs !== undefined && r.ts - fs < 3_600_000_000;
    },
    help: "first seen on this network within the hour",
  },
};

// --------------------------------------------------------------------- AST
export type Node =
  | { t: "all" }
  | { t: "not"; a: Node }
  | { t: "and"; a: Node; b: Node }
  | { t: "or"; a: Node; b: Node }
  | { t: "cmp"; field: string; op: string; value: string }
  | { t: "flag"; name: string }
  | { t: "free"; value: string };

function parse(toks: Tok[]): Node {
  let p = 0;
  const peek = () => toks[p];
  const isWord = (s: string) => {
    const t = toks[p];
    return t.k === "word" && !t.quoted && t.v.toLowerCase() === s;
  };

  function expr(): Node { return orExpr(); }

  function orExpr(): Node {
    let left = andExpr();
    for (;;) {
      if (isWord("or")) { p++; }
      else if (peek().k === "op" && (peek() as any).v === "|") { p++; }
      else return left;
      left = { t: "or", a: left, b: andExpr() };
    }
  }

  function andExpr(): Node {
    let left = unary();
    for (;;) {
      if (isWord("and")) { p++; }
      else if (peek().k === "op" && (peek() as any).v === "&") { p++; }
      else if (peek().k === "eof" || peek().k === "rparen" || isWord("or")) return left;
      left = { t: "and", a: left, b: unary() };
    }
  }

  function unary(): Node {
    if (isWord("not")) { p++; return { t: "not", a: unary() }; }
    const t = peek();
    if (t.k === "word" && !t.quoted && (t.v === "!" || t.v === "-")) { p++; return { t: "not", a: unary() }; }
    if (t.k === "word" && !t.quoted && t.v.length > 1 && (t.v[0] === "!" || t.v[0] === "-")) {
      // "-cached" / "!blocked" written without a space
      toks[p] = { k: "word", v: t.v.slice(1), quoted: false };
      return { t: "not", a: unary() };
    }
    return primary();
  }

  function primary(): Node {
    const t = peek();
    if (t.k === "lparen") {
      p++;
      const inner = expr();
      if (peek().k !== "rparen") throw new QueryError("missing )", p);
      p++;
      return inner;
    }
    if (t.k !== "word") throw new QueryError("expected a term", p);
    p++;
    const next = peek();
    if (next.k === "op" && next.v !== "|" && next.v !== "&") {
      const op = next.v;
      p++;
      const vtok = peek();
      if (vtok.k !== "word") throw new QueryError(`expected a value after ${op}`, p);
      p++;
      const field = t.v.toLowerCase();
      if (!FIELDS[field]) throw new QueryError(`unknown field "${field}"`, p);
      return { t: "cmp", field, op, value: vtok.v.toLowerCase() };
    }
    const w = t.v.toLowerCase();
    if (!t.quoted && ACTION_WORDS[w]) return { t: "cmp", field: "action", op: ":", value: ACTION_WORDS[w] };
    if (!t.quoted && FLAGS[w]) return { t: "flag", name: w };
    return { t: "free", value: w };
  }

  if (peek().k === "eof") return { t: "all" };
  const root = expr();
  if (peek().k !== "eof") throw new QueryError("unexpected trailing input", p);
  return root;
}

/** Parse a query. An empty string matches everything. Throws QueryError. */
export function compile(src: string): Node {
  return parse(lex(src));
}

// ---------------------------------------------------------------- matching
/** Glob match supporting * and ?, anchored. Plain values match as substrings. */
function globMatch(value: string, pattern: string): boolean {
  if (!pattern.includes("*") && !pattern.includes("?")) return value.includes(pattern);
  const rx = "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*").replace(/\?/g, ".") + "$";
  return new RegExp(rx).test(value);
}

function cmpNum(got: number | undefined, op: string, want: number): boolean {
  if (got === undefined || Number.isNaN(want)) return false;
  switch (op) {
    case ">": return got > want;
    case "<": return got < want;
    case ">=": return got >= want;
    case "<=": return got <= want;
    case "!=": return got !== want;
    default: return got === want;
  }
}

export function evaluate(n: Node, r: Row, ctx: Ctx): boolean {
  switch (n.t) {
    case "all": return true;
    case "not": return !evaluate(n.a, r, ctx);
    case "and": return evaluate(n.a, r, ctx) && evaluate(n.b, r, ctx);
    case "or": return evaluate(n.a, r, ctx) || evaluate(n.b, r, ctx);
    case "flag": return FLAGS[n.name].test(r, ctx);
    case "free": {
      const hay = lower(r.qname) + " " + lower(r.client_ip) + " " + lower(r.client_id) +
        " " + lower(r.rule) + " " + lower(r.reason);
      return globMatch(hay, n.value);
    }
    case "cmp": {
      const def = FIELDS[n.field];
      const got = def.get(r, ctx);
      if (def.kind === "num") return cmpNum(got as number, n.op, Number(n.value));
      const s = String(got ?? "");
      if (n.op === "!=") return !globMatch(s, n.value);
      if (n.op === "=") return s === n.value;
      return globMatch(s, n.value);
    }
  }
}

/** A ready-to-use predicate. */
export function matcher(src: string, ctx: Ctx): (r: Row) => boolean {
  const ast = compile(src);
  return (r: Row) => evaluate(ast, r, ctx);
}

// --------------------------------------------------------------- pushdown
/**
 * The part of an expression the server can answer, as query parameters.
 *
 * Only a top-level conjunction of exact equalities on indexed columns is
 * eligible: an `or` or a `not` anywhere above a term means the server would
 * have to return rows the client still needs, so nothing is pushed down for
 * that branch. Whatever is not pushed down is still evaluated locally, so the
 * result set is identical either way — this only decides how much is fetched.
 */
export function pushdown(n: Node): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (x: Node) => {
    if (x.t === "and") { walk(x.a); walk(x.b); return; }
    if (x.t !== "cmp") return;
    const def = FIELDS[x.field];
    if (!def?.param) return;
    if (x.op !== ":" && x.op !== "=") return;
    if (x.value.includes("*") || x.value.includes("?")) {
      // `qname` is a server-side substring match, so a leading/trailing glob
      // can still narrow it; anything else cannot.
      if (def.param === "qname") {
        const core = x.value.replace(/^\*+|\*+$/g, "");
        if (core && !core.includes("*") && !core.includes("?")) out[def.param] = core;
      }
      return;
    }
    // Two equalities on one column contradict; keeping the first is still a
    // superset of the (empty) true result, so the local pass gets it right.
    if (out[def.param] !== undefined) return;
    out[def.param] = x.value;
  };
  walk(n);
  return out;
}

// ---------------------------------------------------------------- explain
/** Render a parsed query back as a sentence, so it can be read before it is trusted. */
export function explain(n: Node): string {
  const phrase = (x: Node): string => {
    switch (x.t) {
      case "all": return "everything";
      case "not": return "not (" + phrase(x.a) + ")";
      case "and": return phrase(x.a) + " and " + phrase(x.b);
      case "or": return phrase(x.a) + " or " + phrase(x.b);
      case "flag": return FLAGS[x.name].help;
      case "free": return `anything mentioning "${x.value}"`;
      case "cmp": {
        const def = FIELDS[x.field];
        if (def.kind === "num") {
          const word: Record<string, string> = {
            ">": "over", "<": "under", ">=": "at least", "<=": "at most",
            "!=": "not", "=": "exactly", ":": "exactly",
          };
          return `${def.noun} ${word[x.op]} ${x.value}`;
        }
        if (x.op === "!=") return `${def.noun} is not ${x.value}`;
        if (x.value.includes("*") || x.value.includes("?")) return `${def.noun} matches ${x.value}`;
        if (x.op === "=") return `${def.noun} is ${x.value}`;
        return `${def.noun} contains ${x.value}`;
      }
    }
  };
  const s = phrase(n);
  return s.charAt(0).toUpperCase() + s.slice(1) + ".";
}

// ------------------------------------------------------------- completion
/** Suggestions for the token under the caret. Fields, then outcome words. */
export function complete(src: string, caret: number): { from: number; items: string[] } {
  let i = caret;
  while (i > 0 && !" \t\n()".includes(src[i - 1])) i--;
  const frag = src.slice(i, caret).toLowerCase();
  const colon = frag.indexOf(":");
  if (colon >= 0) {
    const field = frag.slice(0, colon);
    const want = frag.slice(colon + 1);
    const vals = field === "action" ? Object.values(ACTION_WORDS) : [];
    return { from: i + colon + 1, items: [...new Set(vals)].filter((v) => v.startsWith(want)) };
  }
  const items = [
    ...Object.keys(FIELDS).map((f) => f + ":"),
    ...Object.keys(ACTION_WORDS),
    ...Object.keys(FLAGS),
  ].filter((s) => s.startsWith(frag));
  return { from: i, items: items.slice(0, 12) };
}

/** Field reference for the help sheet, so documentation cannot drift. */
export function reference(): { name: string; kind: string; help: string }[] {
  return [
    ...Object.entries(FIELDS).map(([name, d]) => ({ name: name + ":", kind: d.kind, help: d.help })),
    ...Object.entries(FLAGS).map(([name, d]) => ({ name, kind: "flag", help: d.help })),
  ];
}
