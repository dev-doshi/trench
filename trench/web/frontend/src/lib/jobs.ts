/* Background jobs: what to call them, and what the frame should say about them.
 *
 * The API reports jobs by their scheduler names ("gravity-refresh"), which are
 * for greps, not for people. What deserves the operator's attention is also a
 * judgement, not a display detail — a scheduled sweep that failed once is not
 * news, a blocklist refresh that kept last week's rules is — so it lives here,
 * where it can be tested, and not in a template.
 */

export interface Job {
  name: string;
  interval: number | null;
  next_at: number | null;
  running: boolean;
  started: number | null;
  finished: number | null;
  duration: number | null;
  result: string;          // ok | failed | kept | rejected | skipped | cancelled | ""
  detail: string;
  runs: number;
  failures: number;
  peak_rss: number | null;
  trigger: string;
  runnable: boolean;
}

interface Known { label: string; of: string; rank: number }

/** Names people use, and a line on why each exists. Rank orders the list:
 *  what changes filtering first, housekeeping last. */
const KNOWN: Record<string, Known> = {
  "gravity-refresh": { label: "Blocklist refresh", of: "Fetch every list and rebuild the block table", rank: 0 },
  "reload": { label: "Reload", of: "Re-read the config file, then refresh the lists", rank: 1 },
  "update-check": { label: "Update check", of: "Ask whether a newer release exists", rank: 2 },
  "acme-renew": { label: "Certificate renewal", of: "Renew the TLS certificate before it lapses", rank: 3 },
  "notary": { label: "Answer notary", of: "Ask a second upstream about pinned names", rank: 4 },
  "prewarm": { label: "Cache prewarm", of: "Refresh popular answers before they expire", rank: 5 },
  "retention": { label: "Log retention", of: "Delete stored queries past the retention window", rank: 6 },
  "client-names": { label: "Device names", of: "Learn names from leases and the router", rank: 7 },
  "arp-refresh": { label: "Neighbour table", of: "Read MAC addresses for device identification", rank: 8 },
  "worker-sync": { label: "Worker sync", of: "Pick up tables other workers built", rank: 9 },
  "ratelimit-gc": { label: "Rate-limit cleanup", of: "Forget clients that stopped asking", rank: 10 },
};

export const labelOf = (name: string) => KNOWN[name]?.label
  ?? name.replace(/-/g, " ").replace(/^./, (c) => c.toUpperCase());
export const purposeOf = (name: string) => KNOWN[name]?.of ?? "";

/** Jobs whose failure changes what the network gets. The rest are housekeeping. */
const CONSEQUENTIAL = new Set(["gravity-refresh", "reload", "acme-renew"]);

/** Outcomes that mean "what you asked for did not happen". */
const BAD = new Set(["failed", "kept", "rejected"]);

export function order(jobs: Job[]): Job[] {
  return [...jobs].sort((a, b) =>
    Number(b.running) - Number(a.running)
    || (KNOWN[a.name]?.rank ?? 99) - (KNOWN[b.name]?.rank ?? 99)
    || a.name.localeCompare(b.name));
}

export type Tone = "run" | "bad" | "ok" | "";

export function toneOf(j: Job): Tone {
  if (j.running) return "run";
  if (BAD.has(j.result)) return "bad";
  if (j.result === "ok") return "ok";
  return "";
}

/** What an outcome is called in a sentence. */
export function resultWord(j: Job): string {
  if (j.running) return "running";
  return ({
    ok: "done", failed: "failed", kept: "kept previous", rejected: "rejected",
    skipped: "skipped", cancelled: "cancelled",
  } as Record<string, string>)[j.result] ?? (j.runs ? j.result : "not run yet");
}

/**
 * The one line the frame shows, or null for "nothing worth a glance".
 *
 * Running work is always worth it — a build is minutes of heavy memory on a
 * small box, and "why is the Pi slow" is answered here. A consequential job
 * whose last run went wrong stays up until it next succeeds; a housekeeping
 * job that failed does not, because the Jobs tab is where that is read.
 */
export function headline(jobs: Job[], now: number): { tone: Tone; text: string } | null {
  const running = order(jobs).filter((j) => j.running);
  if (running.length) {
    const j = running[0];
    const took = j.started ? ` · ${duration(now - j.started)}` : "";
    const more = running.length > 1 ? ` +${running.length - 1}` : "";
    return { tone: "run", text: `${labelOf(j.name)}${took}${more}` };
  }
  const bad = order(jobs).find((j) => CONSEQUENTIAL.has(j.name) && BAD.has(j.result));
  if (bad) return { tone: "bad", text: `${labelOf(bad.name)} ${resultWord(bad)}` };
  return null;
}

/** Poll quickly only while something is moving. */
export const pollEvery = (jobs: Job[]) => (jobs.some((j) => j.running) ? 3000 : 15000);

export function duration(s: number | null | undefined): string {
  if (s == null || !isFinite(s)) return "—";
  if (s < 1) return "<1s";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) {
    const m = Math.floor(s / 60), r = Math.round(s % 60);
    return r ? `${m}m ${r}s` : `${m}m`;
  }
  if (s < 86400) {
    const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(s / 86400), h = Math.round((s % 86400) / 3600);
  return h ? `${d}d ${h}h` : `${d}d`;
}

/** "4m ago" / "in 3h" from epoch seconds. */
export const ago = (t: number | null, now: number) =>
  t == null ? "never" : `${duration(Math.max(0, now - t))} ago`;
export const until = (t: number | null, now: number) =>
  t == null ? "not scheduled" : t <= now ? "due now" : `in ${duration(t - now)}`;

export function bytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 ** 3) return `${Math.round(n / 1024 / 1024)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

/** A list URL as the file name people recognise it by. */
export function sourceLabel(url: string): string {
  const tail = url.replace(/[?#].*$/, "").replace(/\/+$/, "").split("/").pop() || url;
  return tail;
}
