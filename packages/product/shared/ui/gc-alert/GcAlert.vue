<script setup lang="ts">
defineProps<{
  level: 'success' | 'info' | 'warning' | 'error'
  title: string
  dismissible?: boolean
}>()

defineEmits<{
  dismiss: []
}>()
</script>

<template>
  <div :class="['gc-alert', `gc-alert--${level}`]">
    <div class="gc-alert-content">
      <div class="gc-alert-title">
        {{ title }}
      </div>
      <div
        v-if="$slots.default"
        class="gc-alert-description"
      >
        <slot />
      </div>
    </div>
    <button
      v-if="dismissible"
      class="gc-alert-dismiss"
      type="button"
      aria-label="Dismiss"
      @click="$emit('dismiss')"
    >
      ✕
    </button>
  </div>
</template>

<style scoped>
.gc-alert {
  display: flex;
  padding: var(--gocode-space-lg);
  border-radius: var(--gocode-radius-md);
  border: 1px solid;
  gap: var(--gocode-space-md);
  font-size: 14px;
}

.gc-alert--success {
  background: color-mix(in srgb, var(--gocode-lead-green) 10%, transparent);
  border-color: color-mix(in srgb, var(--gocode-lead-green) 20%, transparent);
  color: var(--gocode-text-primary);
}

.gc-alert--info {
  background: color-mix(in srgb, var(--gocode-accent) 10%, transparent);
  border-color: color-mix(in srgb, var(--gocode-accent) 20%, transparent);
  color: var(--gocode-text-primary);
}

.gc-alert--warning {
  background: color-mix(in srgb, var(--gocode-warning) 10%, transparent);
  border-color: color-mix(in srgb, var(--gocode-warning) 20%, transparent);
  color: var(--gocode-text-primary);
}

.gc-alert--error {
  background: color-mix(in srgb, var(--gocode-error-coral) 10%, transparent);
  border-color: color-mix(in srgb, var(--gocode-error-coral) 20%, transparent);
  color: var(--gocode-text-primary);
}

.gc-alert-content {
  flex: 1;
  min-width: 0;
}

.gc-alert-title {
  font-weight: 600;
  margin-bottom: 4px;
}

.gc-alert-dismiss {
  display: flex;
  align-items: flex-start;
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  font-size: 14px;
  line-height: 1;
  color: inherit;
  opacity: 0.6;
}

.gc-alert-dismiss:hover {
  opacity: 1;
}
</style>
