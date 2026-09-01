<script setup lang="ts">
// Boot: check session → show Frame, else login form. WS starts after auth.
import { onMounted, ref } from "vue";
import { api, ApiError } from "./lib/api";
import { store } from "./lib/store";
import Frame from "./Frame.vue";
import Toasts from "./ui/Toasts.vue";

const booted = ref(false);
const err = ref("");
const busy = ref(false);
const u = ref(""); const p = ref(""); const c = ref("");

async function boot() {
  try {
    const me = await api.get("/auth/me");
    if (me.user) { store.setUser(me.user); store.startWs(); }
  } catch { /* not logged in */ }
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
    err.value = e instanceof ApiError ? e.message : "login failed";
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
      <h1>DNS<b>Guard</b></h1>
      <div class="sub">Sign in to the console</div>
      <div class="err">{{ err }}</div>
      <form @submit.prevent="login">
        <input v-model="u" placeholder="username" autocomplete="username" autofocus />
        <input v-model="p" type="password" placeholder="password" autocomplete="current-password" />
        <input v-model="c" placeholder="2FA code (if enabled)" inputmode="numeric" autocomplete="one-time-code" />
        <button class="go" :disabled="busy">{{ busy ? "…" : "Sign in" }}</button>
      </form>
    </div>
  </div>
  <Toasts />
</template>
