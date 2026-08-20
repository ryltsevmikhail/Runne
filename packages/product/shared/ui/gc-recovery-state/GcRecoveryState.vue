<script setup lang="ts">
defineProps<{
  state: 'restored' | 'conflict' | 'corrupt'
}>()

defineEmits<{
  resolve: [action: 'local' | 'remote']
  reset: []
}>()
</script>

<template>
  <div class="gc-recovery-state">
    <!-- Restored state -->
    <div
      v-if="state === 'restored'"
      class="gc-recovery-panel gc-recovery-panel--restored"
    >
      <span class="gc-recovery-icon">✓</span>
      <p class="gc-recovery-title">
        Session restored
      </p>
      <p class="gc-recovery-description">
        Your workspace has been recovered.
      </p>
    </div>

    <!-- Conflict state -->
    <div
      v-if="state === 'conflict'"
      class="gc-recovery-panel gc-recovery-panel--conflict"
    >
      <span class="gc-recovery-icon">⚡</span>
      <p class="gc-recovery-title">
        Session conflict
      </p>
      <p class="gc-recovery-description">
        Your local session conflicts with the remote version. Choose which one to keep.
      </p>
      <div class="gc-recovery-actions">
        <button
          class="gc-recovery-btn gc-recovery-btn--local"
          type="button"
          @click="$emit('resolve', 'local')"
        >
          Keep local
        </button>
        <button
          class="gc-recovery-btn gc-recovery-btn--remote"
          type="button"
          @click="$emit('resolve', 'remote')"
        >
          Use remote
        </button>
      </div>
    </div>

    <!-- Corrupt state -->
    <div
      v-if="state === 'corrupt'"
      class="gc-recovery-panel gc-recovery-panel--corrupt"
    >
      <span class="gc-recovery-icon">✕</span>
      <p class="gc-recovery-title">
        Session corrupt
      </p>
      <p class="gc-recovery-description">
        Your session file is corrupt and cannot be recovered. You can start with a fresh workspace.
      </p>
      <div class="gc-recovery-actions">
        <button
          class="gc-recovery-btn gc-recovery-btn--fresh"
          type="button"
          @click="$emit('reset')"
        >
          Start fresh
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.gc-recovery-state {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--runne-space-xl);
}

.gc-recovery-panel {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--runne-space-sm);
  text-align: center;
  max-width: 360px;
}

.gc-recovery-icon {
  font-size: 32px;
  margin-bottom: var(--runne-space-sm);
}

.gc-recovery-panel--restored .gc-recovery-icon {
  color: var(--runne-lead-green);
}

.gc-recovery-panel--conflict .gc-recovery-icon {
  color: var(--runne-warning);
}

.gc-recovery-panel--corrupt .gc-recovery-icon {
  color: var(--runne-error-coral);
}

.gc-recovery-title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--runne-text-primary);
}

.gc-recovery-description {
  margin: 0;
  font-size: 13px;
  color: var(--runne-text-secondary);
  line-height: 1.5;
}

.gc-recovery-actions {
  display: flex;
  gap: var(--runne-space-sm);
  margin-top: var(--runne-space-md);
}

.gc-recovery-btn {
  padding: 8px 16px;
  font-family: var(--runne-font-ui);
  font-size: 13px;
  font-weight: 500;
  border: 1px solid;
  border-radius: var(--runne-radius-md);
  cursor: pointer;
  transition: background var(--runne-motion-fast) ease,
              filter var(--runne-motion-fast) ease;
}

/* Keep local button: primary accent */
.gc-recovery-btn--local {
  background: var(--runne-accent);
  color: var(--runne-text-on-accent);
  border-color: var(--runne-accent);
}

.gc-recovery-btn--local:hover {
  filter: brightness(1.08);
}

/* Use remote button: secondary/outline */
.gc-recovery-btn--remote {
  background: transparent;
  color: var(--runne-text-primary);
  border-color: var(--runne-border);
}

.gc-recovery-btn--remote:hover {
  background: var(--runne-surface);
}

/* Start fresh button: primary accent */
.gc-recovery-btn--fresh {
  background: var(--runne-accent);
  color: var(--runne-text-on-accent);
  border-color: var(--runne-accent);
}

.gc-recovery-btn--fresh:hover {
  filter: brightness(1.08);
}
</style>
