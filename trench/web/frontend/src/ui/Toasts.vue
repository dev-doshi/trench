<script setup lang="ts">
// Toast stack (bottom-left). Fired via store.toast(title, detail?, err?).
// The stack is a polite live region, so a screen reader hears "Copied" without
// being interrupted; an error is an alert, because it means something did not
// happen that the operator thinks did. Clicking a toast dismisses it.
import { store } from "../lib/store";
</script>

<template>
  <div class="toasts" role="status" aria-live="polite" aria-relevant="additions">
    <TransitionGroup name="list">
      <div v-for="t in store.state.toasts" :key="t.id" class="toast" :class="{ err: t.err }"
           :role="t.err ? 'alert' : undefined" @click="store.dismissToast(t.id)">
        <div class="t">{{ t.title }}</div>
        <div v-if="t.detail" class="d">{{ t.detail }}</div>
      </div>
    </TransitionGroup>
  </div>
</template>
