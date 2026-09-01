import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import App from "./App.vue";
import "./styles/bailiwick.css";

// Applied before the app mounts: doing it in a component lets the default skin
// paint first and then swap, which is a visible flash on every load.
document.documentElement.dataset.skin = localStorage.getItem("bw_skin") || "auto";

/* One surface plus nine places. Each route is a question an operator has, not a
 * subsystem of the resolver — which is why there is no "dashboard" and no
 * "advanced". */
const routes = [
  { path: "/", name: "browse", component: () => import("./views/Browse.vue") },
  { path: "/live", name: "live", component: () => import("./views/Live.vue") },
  { path: "/log", name: "log", component: () => import("./views/Log.vue") },
  { path: "/history", name: "history", component: () => import("./views/History.vue") },
  { path: "/policy", name: "policy", component: () => import("./views/Policy.vue") },
  { path: "/breakage", name: "breakage", component: () => import("./views/Breakage.vue") },
  { path: "/devices", name: "devices", component: () => import("./views/Devices.vue") },
  { path: "/resolver", name: "resolver", component: () => import("./views/Resolver.vue") },
  { path: "/privacy", name: "privacy", component: () => import("./views/Privacy.vue") },
  { path: "/audit", name: "audit", component: () => import("./views/Audit.vue") },
  { path: "/settings", name: "settings", component: () => import("./views/Settings.vue") },

  // bookmarks from the previous two designs still resolve
  { path: "/pulse", redirect: "/live" },
  { path: "/explore", redirect: "/history" },
  { path: "/rules", redirect: "/policy" },
  { path: "/collateral", redirect: "/breakage" },
  { path: "/clients", redirect: "/devices" },
  { path: "/system", redirect: "/resolver" },
  { path: "/activity", redirect: "/" },
  { path: "/overview", redirect: "/" },
];

const router = createRouter({ history: createWebHistory(), routes });
createApp(App).use(router).mount("#app");
