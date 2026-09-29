<script setup lang="ts">
// Boot: check session → show Frame, else login form. WS starts after auth.
import { onMounted, ref } from "vue";
import { api, ApiError, whenUnauthorized } from "./lib/api";
import { store } from "./lib/store";
import Frame from "./Frame.vue";
import Toasts from "./ui/Toasts.vue";

const booted = ref(false);
const err = ref("");
const busy = ref(false);
const u = ref(""); const p = ref(""); const c = ref("");

/** The session ended while the console was open. Go back to sign-in and say
 *  why — a console that silently stops updating is worse than one that asks. */
function expired() {
  if (!store.state.user) return;
  store.stopWs();
  store.setUser(null);
  err.value = "Your session ended. Sign in again to continue.";
}
whenUnauthorized(expired);
store.onSessionExpired(expired);

async function boot() {
  try {
    const me = await api.get("/auth/me");
    if (me.user) { store.setUser(me.user); store.startWs(); }
  } catch (e) {
    // not signed in is the ordinary case; a daemon that is not there is not
    if (e instanceof ApiError && e.status === 0) err.value = e.message;
  }
  booted.value = true;
}

async function login() {
  err.value = ""; busy.value = true;
  try {
    await api.post("/auth/login", { name: u.value, password: p.value, code: c.value });
    const me = await api.get("/auth/me");
    store.setUser(me.user);
    store.startWs();
  } catch (e) {
    err.value = !(e instanceof ApiError) ? "Sign-in failed."
      : e.status === 401 ? "That name, password or code was not accepted."
      : e.status === 429 ? "Too many attempts. Wait a minute, then try again."
      : e.message;
  } finally {
    busy.value = false;
  }
}

onMounted(boot);
</script>

<template>
  <div v-if="!booted" />
  <Frame v-else-if="store.state.user" />
  <div v-else class="login">
    <div class="box">
      <h1>Tre<b>nch</b></h1>
      <div class="sub">Sign in to the console</div>
      <div class="err" id="login-err" role="alert">{{ err }}</div>
      <form @submit.prevent="login" :aria-describedby="err ? 'login-err' : undefined">
        <input v-model="u" placeholder="username" aria-label="Username" autocomplete="username"
               autocapitalize="off" spellcheck="false" required autofocus />
        <input v-model="p" type="password" placeholder="password" aria-label="Password"
               autocomplete="current-password" required />
        <input v-model="c" placeholder="2FA code (if enabled)" aria-label="Two-factor code, if enabled"
               inputmode="numeric" autocomplete="one-time-code" />
        <button class="go" :disabled="busy" :aria-busy="busy">{{ busy ? "Signing in…" : "Sign in" }}</button>
      </form>
    </div>
  </div>
  <Toasts />
</template>
