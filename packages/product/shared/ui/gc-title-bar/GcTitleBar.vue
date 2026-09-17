<script setup lang="ts">
import primaryLogo from '../assets/runne-primary-logo.svg'
import primaryLogoLight from '../assets/runne-primary-logo-light.svg'

defineProps<{ nativeWindowControls?: boolean; hideBrand?: boolean }>()
</script>

<template>
  <header class="gc-title-bar">
    <div v-if="nativeWindowControls" class="gc-title-bar-native-controls" aria-hidden="true" />
    <div v-else class="gc-title-bar-controls">
      <span class="gc-title-bar-dot gc-title-bar-dot--close" />
      <span class="gc-title-bar-dot gc-title-bar-dot--minimize" />
      <span class="gc-title-bar-dot gc-title-bar-dot--maximize" />
    </div>
    <div v-if="!hideBrand" class="gc-title-bar-brand">
      <slot name="brand">
        <img
          class="gc-title-bar-logo gc-title-bar-logo--dark"
          :src="primaryLogo"
          alt="Runne"
        >
        <img
          class="gc-title-bar-logo gc-title-bar-logo--light"
          :src="primaryLogoLight"
          alt="Runne"
        >
      </slot>
    </div>
    <div class="gc-title-bar-drag" />
  </header>
</template>

<style scoped>
.gc-title-bar {
  display: flex;
  align-items: center;
  height: 38px;
  padding: 0 var(--runne-space-md);
  background: var(--runne-canvas);
  border-bottom: 1px solid var(--runne-border);
  user-select: none;
  -webkit-app-region: drag;
}

.gc-title-bar-controls {
  display: flex;
  gap: 8px;
  -webkit-app-region: no-drag;
}

.gc-title-bar-native-controls {
  flex: 0 0 68px;
}

.gc-title-bar-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.gc-title-bar-dot--close { background: #FF5F57; }
.gc-title-bar-dot--minimize { background: #FEBC2E; }
.gc-title-bar-dot--maximize { background: #28C840; }

.gc-title-bar-brand {
  flex: 1;
  text-align: center;
}

.gc-title-bar-logo {
  display: block;
  width: 70px;
  height: auto;
}

.gc-title-bar-logo--light {
  display: none;
}

:global([data-theme='light'] .gc-title-bar-logo--dark) {
  display: none;
}

:global([data-theme='light'] .gc-title-bar-logo--light) {
  display: block;
}

.gc-title-bar-drag {
  width: 112px;
}
</style>
