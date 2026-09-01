/* Name handling, and the rules about what may be learned from a name.
 *
 * Two jobs:
 *
 *   1. Typography. Domain lists align on the registrable boundary, so eTLD+1
 *      forms a hard vertical column and subdomain sprawl reads as growth to the
 *      left. Scanning two hundred names, families stack visibly.
 *   2. Corroboration. Everything here is derived from the name itself or from
 *      data already on this machine. No function in this module can cause a
 *      byte to leave the box — that is a property worth stating, because DNS
 *      enrichment is exactly where privacy tooling usually leaks.
 */

// --------------------------------------------------------- public suffixes
/* A curated subset of the Public Suffix List: the multi-label suffixes common
 * enough to matter for reading a home or small-office network, plus the hosting
 * suffixes that behave like registries. Everything else falls back to
 * last-two-labels, which is correct for the overwhelming majority of names.
 *
 * This is a rendering and grouping aid, not a security boundary: nothing here
 * decides whether a name is blocked. If it ever needs to be authoritative,
 * ship the full list as a bulk file — that is an egress-free refresh, unlike a
 * per-name lookup.
 */
const MULTI_SUFFIX = new Set([
  "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "lg.jp",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "com.br", "net.br", "org.br", "gov.br",
  "co.in", "net.in", "org.in", "gen.in", "firm.in",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "co.za", "org.za", "net.za", "gov.za",
  "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
  "com.pl", "com.ua", "com.ru", "com.br", "com.co", "com.pe", "com.ph",
  "co.kr", "or.kr", "ne.kr", "go.kr",
  "gov.us", "k12.us",
  // effective suffixes that behave like registries for content
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
  "netlify.app", "herokuapp.com", "cloudfront.net", "azurewebsites.net",
  "s3.amazonaws.com", "appspot.com", "web.app", "firebaseapp.com",
  "blogspot.com", "duckdns.org", "dynv6.net", "no-ip.org", "ddns.net",
]);

const clean = (name: string) => name.replace(/\.$/, "").toLowerCase();

/** eTLD+1, by known rule where possible and by last-two-labels otherwise. */
export function registrable(name: string): string {
  const parts = clean(name).split(".");
  if (parts.length <= 2) return parts.join(".");
  // Longest matching suffix wins: a rule of k labels makes the registrable
  // domain k+1 labels long.
  for (let k = 3; k >= 2; k--) {
    if (parts.length <= k) continue;
    if (MULTI_SUFFIX.has(parts.slice(-k).join("."))) return parts.slice(-(k + 1)).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * Split a name for boundary-aligned rendering.
 * `sub` grows leftward, `reg` is the column everything aligns on.
 */
export function align(name: string): { sub: string; reg: string } {
  const c = clean(name);
  const reg = registrable(c);
  const sub = c.length > reg.length ? c.slice(0, c.length - reg.length - 1) : "";
  return { sub, reg };
}

// ------------------------------------------------------------- name shape
export interface Shape {
  labels: number;
  longest: number;
  entropy: number;        // bits per character of the leftmost label
  punycode: boolean;
  digitHeavy: boolean;    // a label that is mostly digits — often generated
  hexish: boolean;        // a label that looks like a hex identifier
  mixedScript: boolean;   // labels combining scripts, the homoglyph shape
}

/** Shannon entropy per character. Random-looking labels score high. */
function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function shape(name: string): Shape {
  const c = clean(name);
  const labels = c.split(".");
  const first = labels[0] || "";
  const digits = (first.match(/\d/g) || []).length;
  return {
    labels: labels.length,
    longest: Math.max(0, ...labels.map((l) => l.length)),
    entropy: Number(entropy(first).toFixed(2)),
    punycode: c.includes("xn--"),
    digitHeavy: first.length > 5 && digits / first.length > 0.5,
    hexish: /^[0-9a-f]{12,}$/.test(first),
    // Latin mixed with Cyrillic/Greek in one label is the classic lookalike.
    mixedScript: labels.some((l) => /[a-z]/.test(l) && /[Ͱ-ϿЀ-ӿ]/.test(l)),
  };
}

// ------------------------------------------------------- answer topology
export type AddrClass = "loopback" | "private" | "cgnat" | "linklocal" | "unspecified" | "public" | "not-an-address";

/** Classify an answer record's address without asking anyone anything. */
export function classifyAddr(text: string): AddrClass {
  const v = text.trim();
  if (/^[0-9.]+$/.test(v)) {
    const o = v.split(".").map(Number);
    if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n > 255)) return "not-an-address";
    if (o[0] === 0) return "unspecified";
    if (o[0] === 127) return "loopback";
    if (o[0] === 10) return "private";
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return "private";
    if (o[0] === 192 && o[1] === 168) return "private";
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return "cgnat";
    if (o[0] === 169 && o[1] === 254) return "linklocal";
    return "public";
  }
  if (v.includes(":")) {
    const l = v.toLowerCase();
    if (l === "::" ) return "unspecified";
    if (l === "::1") return "loopback";
    if (l.startsWith("fe80")) return "linklocal";
    if (/^f[cd]/.test(l)) return "private";
    return "public";
  }
  return "not-an-address";
}

/** Parse the stored answers column into records, tolerating anything. */
export function answerList(answers: string | undefined): string[] {
  if (!answers) return [];
  try {
    const v = JSON.parse(answers);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return answers ? [answers] : [];
  }
}

/**
 * The sinkhole addresses this product answers with. A blocked name whose answer
 * is one of these is the resolver's own refusal, not an origin's address, and
 * the exhibit must not present it as though something resolved.
 */
export function isSinkhole(text: string): boolean {
  const v = text.trim();
  return v === "0.0.0.0" || v === "::" || v === "127.0.0.1" || v === "::1";
}

