<script setup lang="ts">
interface Tab {
  id: string
  label: string
  badge?: string | number
}

interface WorkspaceFile {
  id: string
  label: string
  depth?: number
}

defineProps<{
  tabs: Tab[]
  activeTab: string
  panelState: 'empty' | 'loading' | 'unavailable' | 'ready'
  files?: readonly WorkspaceFile[]
}>()

defineEmits<{
  selectTab: [id: string]
  retry: []
}>()
</script>

<template>
  <div class="gc-workspace-panel">
    <div class="gc-workspace-panel-tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        :class="['gc-workspace-panel-tab', { 'gc-workspace-panel-tab--active': tab.id === activeTab }]"
        type="button"
        @click="$emit('selectTab', tab.id)"
      >
        <span class="gc-workspace-panel-tab-label">{{ tab.label }}</span>
        <span v-if="tab.badge != null" class="gc-workspace-panel-tab-badge">{{ tab.badge }}</span>
      </button>
    </div>

    <div class="gc-workspace-panel-content">
      <!-- Empty state -->
      <ul v-if="panelState === 'ready'" class="gc-workspace-panel-file-tree" aria-label="Workspace files">
        <li v-for="file in files ?? []" :key="file.id" :style="{ paddingInlineStart: `${file.depth ?? 0}rem` }">
          {{ file.label }}
        </li>
      </ul>

      <div v-else-if="panelState === 'empty'" class="gc-workspace-panel-empty">
        <span class="gc-workspace-panel-empty-icon">📂</span>
        <p class="gc-workspace-panel-empty-title">Nothing here yet</p>
        <p class="gc-workspace-panel-empty-subtitle">Open a file to get started</p>
      </div>

      <!-- Loading state -->
      <div v-else-if="panelState === 'loading'" class="gc-workspace-panel-loading">
        <div class="gc-workspace-panel-skeleton" />
        <div class="gc-workspace-panel-skeleton gc-workspace-panel-skeleton--short" />
        <div class="gc-workspace-panel-skeleton gc-workspace-panel-skeleton--medium" />
      </div>

      <!-- Unavailable state -->
      <div v-else-if="panelState === 'unavailable'" class="gc-workspace-panel-unavailable">
        <span class="gc-workspace-panel-unavailable-icon">⚠️</span>
        <p class="gc-workspace-panel-unavailable-title">Panel unavailable</p>
        <button class="gc-workspace-panel-retry-btn" type="button" @click="$emit('retry')">Retry</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.gc-workspace-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--gocode-surface);
}

.gc-workspace-panel-tabs {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--gocode-border);
  padding: 0 var(--gocode-space-lg);
}

.gc-workspace-panel-tab {
  display: inline-flex;
  align-items: center;
  gap: var(--gocode-space-sm);
  padding: var(--gocode-space-sm) var(--gocode-space-md);
  border: none;
  background: transparent;
  color: var(--gocode-text-secondary);
  font-family: var(--gocode-font-ui);
  font-size: 13px;
  cursor: pointer;
  position: relative;
  transition: color var(--gocode-motion-fast) ease;
}

.gc-workspace-panel-tab:hover {
  color: var(--gocode-text-primary);
}

.gc-workspace-panel-tab--active {
  color: var(--gocode-accent);
}

.gc-workspace-panel-tab--active::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: var(--gocode-space-md);
  right: var(--gocode-space-md);
  height: 2px;
  background: var(--gocode-accent);
  border-radius: 1px;
}

.gc-workspace-panel-tab-label {
  white-space: nowrap;
}

.gc-workspace-panel-tab-badge {
  font-size: 11px;
  padding: 1px 6px;
  border-radius: var(--gocode-radius-sm);
  background: var(--gocode-surface-raised);
  color: var(--gocode-ui-muted);
}

.gc-workspace-panel-content {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--gocode-space-lg);
}

.gc-workspace-panel-file-tree {
  width: 100%;
  margin: 0;
  padding: 0;
  color: var(--gocode-text-primary);
  font-family: var(--gocode-font-mono);
  font-size: 13px;
  list-style: none;
}

.gc-workspace-panel-file-tree li {
  padding-block: var(--gocode-space-xs);
}

/* Empty state */
.gc-workspace-panel-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--gocode-space-sm);
  text-align: center;
}

.gc-workspace-panel-empty-icon {
  font-size: 32px;
  margin-bottom: var(--gocode-space-sm);
}

.gc-workspace-panel-empty-title {
  margin: 0;
  font-size: 14px;
  font-weight: 500;
  color: var(--gocode-text-primary);
}

.gc-workspace-panel-empty-subtitle {
  margin: 0;
  font-size: 12px;
  color: var(--gocode-ui-muted);
}

/* Loading state */
.gc-workspace-panel-loading {
  display: flex;
  flex-direction: column;
  gap: var(--gocode-space-sm);
  width: 100%;
  max-width: 300px;
}

.gc-workspace-panel-skeleton {
  height: 14px;
  border-radius: var(--gocode-radius-sm);
  background: var(--gocode-surface-raised);
  animation: skeleton-pulse 1.5s ease-in-out infinite;
}

.gc-workspace-panel-skeleton--short {
  width: 60%;
}

.gc-workspace-panel-skeleton--medium {
  width: 80%;
}

@keyframes skeleton-pulse {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 0.8; }
}

@media (prefers-reduced-motion: reduce) {
  .gc-workspace-panel-skeleton {
    animation: none;
  }
}

/* Unavailable state */
.gc-workspace-panel-unavailable {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--gocode-space-sm);
  text-align: center;
}

.gc-workspace-panel-unavailable-icon {
  font-size: 32px;
  margin-bottom: var(--gocode-space-sm);
}

.gc-workspace-panel-unavailable-title {
  margin: 0;
  font-size: 14px;
  font-weight: 500;
  color: var(--gocode-error-coral);
}

.gc-workspace-panel-retry-btn {
  margin-top: var(--gocode-space-sm);
  padding: 6px 16px;
  font-family: var(--gocode-font-ui);
  font-size: 13px;
  font-weight: 500;
  color: var(--gocode-text-on-accent);
  background: var(--gocode-accent);
  border: none;
  border-radius: var(--gocode-radius-md);
  cursor: pointer;
  transition: filter var(--gocode-motion-fast) ease;
}

.gc-workspace-panel-retry-btn:hover {
  filter: brightness(1.08);
}
</style>
