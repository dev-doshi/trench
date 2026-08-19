<script setup lang="ts">
// Toast stack (bottom-right). Fired via store.toast(title, detail?, err?).
import { store } from "../lib/store";
</script>

<template>
  <div class="toasts">
    <TransitionGroup name="list">
      <div v-for="t in store.state.toasts" :key="t.id" class="toast" :class="{ err: t.err }">
        <div class="t">{{ t.title }}</div>
        <div v-if="t.detail" class="d">{{ t.detail }}</div>
      </div>
    </TransitionGroup>
  </div>
</template>
