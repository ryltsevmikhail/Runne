<script setup lang="ts">
</script>

<template>
  <header class="gc-title-bar">
    <div class="gc-title-bar-controls">
      <span class="gc-title-bar-dot gc-title-bar-dot--close" />
      <span class="gc-title-bar-dot gc-title-bar-dot--minimize" />
      <span class="gc-title-bar-dot gc-title-bar-dot--maximize" />
    </div>
    <div class="gc-title-bar-brand">
      <slot name="brand">
        <span class="gc-title-bar-lockup">GOCODE</span>
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
  padding: 0 var(--gocode-space-md);
  background: var(--gocode-canvas);
  border-bottom: 1px solid var(--gocode-border);
  user-select: none;
  -webkit-app-region: drag;
}

.gc-title-bar-controls {
  display: flex;
  gap: 8px;
  -webkit-app-region: no-drag;
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

.gc-title-bar-lockup {
  font-size: 13px;
  font-weight: 600;
  color: var(--gocode-text-secondary);
  letter-spacing: 1px;
}

.gc-title-bar-drag {
  width: 112px;
}
</style>
