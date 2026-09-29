/* Job wording + attention tests.  node src/lib/jobs.test.ts */
import {
  ago, bytes, duration, headline, labelOf, order, pollEvery, resultWord, sourceLabel,
  toneOf, until, type Job,
} from "./jobs.ts";

let pass = 0;
const fails: string[] = [];
const eq = (w: string, g: unknown, e: unknown) => {
  const a = JSON.stringify(g), b = JSON.stringify(e);
  a === b ? pass++ : fails.push(`${w}\n      got  ${a}\n      want ${b}`);
};

const NOW = 1_800_000_000;
const job = (o: Partial<Job> = {}): Job => ({
  name: "retention", interval: 3600, next_at: null, running: false, started: null,
  finished: null, duration: null, result: "", detail: "", runs: 0, failures: 0,
  peak_rss: null, trigger: "", runnable: true, ...o,
});

// ── headline: what earns a place in the frame ──
eq("quiet when nothing happened", headline([job(), job({ name: "prewarm" })], NOW), null);
eq("a running build is shown with how long it has taken",
   headline([job({ name: "gravity-refresh", running: true, started: NOW - 75 })], NOW),
   { tone: "run", text: "Blocklist refresh · 1m 15s" });
eq("several running: the most consequential, plus a count",
   headline([job({ name: "prewarm", running: true, started: NOW - 2 }),
             job({ name: "gravity-refresh", running: true, started: NOW - 10 })], NOW),
   { tone: "run", text: "Blocklist refresh · 10s +1" });
eq("a refresh that kept the previous rules stays visible",
   headline([job({ name: "gravity-refresh", result: "kept", runs: 1 })], NOW),
   { tone: "bad", text: "Blocklist refresh kept previous" });
eq("a rejected refresh is visible",
   headline([job({ name: "gravity-refresh", result: "rejected", runs: 1 })], NOW)?.tone, "bad");
eq("a failed housekeeping sweep is not frame news",
   headline([job({ name: "retention", result: "failed", runs: 3 })], NOW), null);
eq("running outranks a stale failure",
   headline([job({ name: "gravity-refresh", result: "failed" }),
             job({ name: "reload", running: true, started: NOW })], NOW)?.tone, "run");

// ── order and tone ──
eq("running first, then by consequence",
   order([job({ name: "ratelimit-gc" }), job({ name: "gravity-refresh" }),
          job({ name: "prewarm", running: true })]).map((j) => j.name),
   ["prewarm", "gravity-refresh", "ratelimit-gc"]);
eq("unknown jobs sort last, by name",
   order([job({ name: "zz" }), job({ name: "aa" }), job({ name: "reload" })]).map((j) => j.name),
   ["reload", "aa", "zz"]);
eq("tones", [job({ running: true }), job({ result: "kept" }), job({ result: "ok" }), job()].map(toneOf),
   ["run", "bad", "ok", ""]);
eq("words", [job({ runs: 0 }), job({ result: "kept", runs: 1 }), job({ result: "ok", runs: 2 })].map(resultWord),
   ["not run yet", "kept previous", "done"]);
eq("labels", [labelOf("gravity-refresh"), labelOf("some-new-job")], ["Blocklist refresh", "Some new job"]);
eq("poll fast only while running", [pollEvery([job()]), pollEvery([job({ running: true })])], [15000, 3000]);

// ── formatting ──
eq("durations", [0.2, 5, 60, 125, 3600, 3660, 90000, null].map(duration),
   ["<1s", "5s", "1m", "2m 5s", "1h", "1h 1m", "1d 1h", "—"]);
eq("ago / until", [ago(NOW - 90, NOW), ago(null, NOW), until(NOW + 7200, NOW), until(NOW - 1, NOW), until(null, NOW)],
   ["1m 30s ago", "never", "in 2h", "due now", "not scheduled"]);
eq("bytes", [bytes(512 * 1024), bytes(146 * 1024 * 1024), bytes(1.5 * 1024 ** 3), bytes(null)],
   ["512 KB", "146 MB", "1.5 GB", "—"]);
eq("source labels", [
  sourceLabel("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt"),
  sourceLabel("data/default_blocklist.txt"), sourceLabel("https://x.example/list/?v=2")],
   ["ultimate.txt", "default_blocklist.txt", "list"]);

if (fails.length) {
  console.error(`jobs: ${fails.length} failed, ${pass} passed\n  ` + fails.join("\n  "));
  process.exit(1);
}
console.log(`jobs: ${pass} passed`);
