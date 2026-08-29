<script setup lang="ts">
import { GcTitleBar } from '@gocode/product/shared/ui'
</script>

<template>
  <GcTitleBar
    class="desktop-title-bar"
    data-tauri-drag-region
    aria-hidden="true"
  >
    <template #brand>
      <span class="runne-title-lockup">Runne<span aria-hidden="true">.</span></span>
    </template>
  </GcTitleBar>
</template>

<style scoped>
.runne-title-lockup {
  color: var(--gocode-text-primary);
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  font-weight: 700;
  letter-spacing: -.02em;
}

.runne-title-lockup span {
  color: var(--gocode-accent);
}
</style>
