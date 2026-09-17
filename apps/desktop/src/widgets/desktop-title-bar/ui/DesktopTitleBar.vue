<script setup lang="ts">
import { GcTitleBar } from '@runne/product/shared/ui'
</script>

<template>
  <GcTitleBar
    class="desktop-title-bar"
    native-window-controls
    hide-brand
    data-tauri-drag-region="deep"
    aria-hidden="true"
  />
</template>
