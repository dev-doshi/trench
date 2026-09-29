/* One poll of /jobs for the whole console.
 *
 * The frame's indicator and the Jobs tab both want it; two timers would ask the
 * box the same question twice, and on the hardware this runs on the console's
 * own polling is a measurable share of what the API serves. Reference-counted:
 * the poll runs while anything is watching and stops when nothing is.
 */
import { onMounted, onUnmounted, reactive } from "vue";
import { api } from "./api";
import { pollEvery, type Job } from "./jobs";

export interface JobFeed {
  jobs: Job[];
  building: boolean;
  memory: { rss: number | null; cgroup_current: number | null;
            cgroup_peak: number | null; cgroup_max: number | null };
  table: { built_at?: number | null; rules?: number | null; complete?: boolean | null;
           matches_config?: boolean; domains?: number | null };
  sources: { url: string; last_update: number; rule_count: number; status: string; error: string }[];
  now: number;
  loaded: boolean;
  error: string;
  /** Offset between this browser's clock and the box's, so "12s ago" is not
   *  wrong by however far apart the two clocks have drifted. */
  skew: number;
}

export const feed = reactive<JobFeed>({
  jobs: [], building: false,
  memory: { rss: null, cgroup_current: null, cgroup_peak: null, cgroup_max: null },
  table: {}, sources: [], now: Date.now() / 1000, loaded: false, error: "", skew: 0,
});

let watchers = 0;
let timer: ReturnType<typeof setTimeout> | null = null;
let inflight: Promise<void> | null = null;

export function refresh(): Promise<void> {
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      const r = await api.get("/jobs");
      Object.assign(feed, r, { loaded: true, error: "",
                               skew: r.now - Date.now() / 1000 });
    } catch (e: any) {
      feed.error = e?.message || "jobs unavailable";
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

function schedule() {
  if (timer) clearTimeout(timer);
  if (!watchers) { timer = null; return; }
  timer = setTimeout(async () => {
    // A hidden tab has nobody to show it to; check again when it is back.
    if (document.visibilityState !== "hidden") await refresh();
    schedule();
  }, pollEvery(feed.jobs));
}

/** Watch the feed for the life of the calling component. */
export function useJobFeed() {
  onMounted(() => {
    if (watchers++ === 0) refresh().then(schedule);
  });
  onUnmounted(() => {
    if (--watchers === 0 && timer) { clearTimeout(timer); timer = null; }
  });
  return feed;
}

/** Ask for a quick follow-up, e.g. right after starting a job by hand. */
export function soon() {
  setTimeout(() => refresh().then(schedule), 400);
}

/** Box time, in epoch seconds. */
export const boxNow = () => Date.now() / 1000 + feed.skew;
