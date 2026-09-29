import { createApp } from "vue";
import { createRouter, createWebHistory, type RouteLocationNormalized } from "vue-router";
import App from "./App.vue";
import "./styles/bailiwick.css";
import { local } from "./lib/local";

// Applied before the app mounts: doing it in a component lets the default skin
// paint first and then swap, which is a visible flash on every load.
document.documentElement.dataset.skin = local.get("bw_skin") || "auto";

/* A front page plus the places. Each place is a question an operator has, not a
 * subsystem of the resolver — which is why there is no "advanced". Privacy,
 * Audit and Jobs are Settings tabs: they are consulted while changing the
 * knobs, not visited to watch the network. */
const routes = [
  {
    path: "/", name: "overview", component: () => import("./views/Overview.vue"),
    // Browse lived here, and its links carry the query in the URL
    beforeEnter: (to: RouteLocationNormalized) =>
      Object.keys(to.query).length ? { path: "/browse", query: to.query } : true,
  },
  { path: "/browse", name: "browse", component: () => import("./views/Browse.vue") },
  { path: "/live", name: "live", component: () => import("./views/Live.vue") },
  { path: "/log", name: "log", component: () => import("./views/Log.vue") },
  { path: "/history", name: "history", component: () => import("./views/History.vue") },
  { path: "/policy", name: "policy", component: () => import("./views/Policy.vue") },
  { path: "/breakage", name: "breakage", component: () => import("./views/Breakage.vue") },
  { path: "/devices", name: "devices", component: () => import("./views/Devices.vue") },
  { path: "/resolver", name: "resolver", component: () => import("./views/Resolver.vue") },
  { path: "/privacy", redirect: { path: "/settings", query: { tab: "privacy" } } },
  { path: "/audit", redirect: { path: "/settings", query: { tab: "audit" } } },
  { path: "/jobs", redirect: { path: "/settings", query: { tab: "jobs" } } },
  { path: "/settings", name: "settings", component: () => import("./views/Settings.vue") },

  // bookmarks from the previous two designs still resolve
  { path: "/pulse", redirect: "/live" },
  { path: "/explore", redirect: "/history" },
  { path: "/rules", redirect: "/policy" },
  { path: "/collateral", redirect: "/breakage" },
  { path: "/clients", redirect: "/devices" },
  { path: "/system", redirect: "/resolver" },
  { path: "/activity", redirect: "/browse" },
  { path: "/overview", redirect: "/" },
];

const router = createRouter({ history: createWebHistory(), routes });

// A tab left open across an upgrade still runs the previous build, and the
// views it lazy-loads were deleted with it. Loading the page fresh fetches the
// current build. At most once a minute, and never when storage cannot remember
// that it tried, so a server that really is broken shows its error instead of
// reloading forever.
router.onError((_err, to) => {
  const now = String(Date.now());
  if (Date.now() - Number(local.get("bw_reloaded") || 0) < 60_000) return;
  local.set("bw_reloaded", now);
  if (local.get("bw_reloaded") === now) location.assign(to.fullPath);
});

createApp(App).use(router).mount("#app");
