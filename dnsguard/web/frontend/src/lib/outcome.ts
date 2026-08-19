/* What happened to a query, in the words people already use for it.
 *
 * An earlier version of this file called blocking "blocked" and a cache hit
 * "no round trip". Both are more precise than the common words and both were a
 * mistake: finding the blocked rows at a glance is the main job of every screen
 * in this console, and a reader should never have to translate.
 */
import type { Row } from "./qlang.ts";

export type Kind = "cache" | "upstream" | "local" | "blocked" | "failed" | "unknown";

export interface Outcome {
  kind: Kind;
  /** short label for a column head or legend */
  label: string;
  /** full sentence for the evidence panel */
  sentence: string;
  /** did the network get an answer at all */
  answered: boolean;
  /** did the query leave this machine */
  travelled: boolean;
}

const OUTCOMES: Record<Kind, Omit<Outcome, "kind">> = {
  cache: { label: "cached", sentence: "answered from this resolver's cache", answered: true, travelled: false },
  upstream: { label: "forwarded", sentence: "forwarded to an upstream resolver", answered: true, travelled: true },
  local: { label: "local", sentence: "answered locally", answered: true, travelled: false },
  blocked: { label: "blocked", sentence: "blocked by policy", answered: false, travelled: false },
  failed: { label: "failed", sentence: "no answer could be obtained", answered: false, travelled: true },
  unknown: { label: "unrecorded", sentence: "the outcome was not recorded", answered: false, travelled: false },
};

/** Display order everywhere: what you came to look for first. */
export const KINDS: Kind[] = ["blocked", "failed", "cache", "upstream", "local", "unknown"];

const BLOCKED = new Set(["blocked", "block", "refused", "ratelimited", "safesearch"]);
const LOCAL = new Set(["authoritative", "rewrite"]);

export function kindOf(r: Row): Kind {
  const action = (r.action || "").toLowerCase();
  if (!action) return "unknown";
  if (action === "failed" || (r.rcode || "").toLowerCase() === "servfail") return "failed";
  if (BLOCKED.has(action)) return "blocked";
  if (action === "cached") return "cache";
  if (LOCAL.has(action)) return "local";
  return "upstream";
}

export function outcomeOf(r: Row): Outcome {
  const kind = kindOf(r);
  return { kind, ...OUTCOMES[kind] };
}

export const meta = (k: Kind): Omit<Outcome, "kind"> => OUTCOMES[k];

/**
 * A cache hit the resolver could not refresh is still a hit, but the operator
 * needs to know the data is past its TTL. Kept separate from `kind` because it
 * is an annotation on an answer, not a different answer.
 */
export function isStale(r: Row): boolean {
  return kindOf(r) === "cache" && (r.reason || "").toLowerCase().startsWith("stale");
}

/** Was the deciding rule written by this operator rather than pulled from a list? */
export function isAuthored(r: Row): boolean {
  return (r.source || "").toLowerCase() === "custom" && !!r.rule;
}

/** CSS custom property carrying this outcome's fill. */
export const fillVar = (k: Kind): string => `var(--o-${k})`;
