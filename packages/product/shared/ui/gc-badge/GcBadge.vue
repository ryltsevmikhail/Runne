<script setup lang="ts">
defineProps<{
  status: 'ready' | 'error' | 'running' | 'offline' | 'review' | 'streaming'
}>()
</script>

<template>
  <span :class="['gc-badge', `gc-badge--${status}`]">
    <span
      v-if="status === 'running' || status === 'streaming'"
      class="gc-badge-dot"
    />
    <slot />
  </span>
</template>

<style scoped>
.gc-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  font-size: 12px;
  font-weight: 500;
  border-radius: var(--gocode-radius-lg);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.gc-badge--ready {
  background: color-mix(in srgb, var(--gocode-lead-green) 15%, transparent);
  color: var(--gocode-lead-green);
}

.gc-badge--error {
  background: color-mix(in srgb, var(--gocode-error-coral) 15%, transparent);
  color: var(--gocode-error-coral);
}

.gc-badge--running {
  background: color-mix(in srgb, var(--gocode-accent) 15%, transparent);
  color: var(--gocode-accent);
}

.gc-badge--offline {
  background: color-mix(in srgb, var(--gocode-ui-muted) 15%, transparent);
  color: var(--gocode-ui-muted);
}

.gc-badge--review {
  background: color-mix(in srgb, var(--gocode-review-violet) 15%, transparent);
  color: var(--gocode-review-violet);
}

.gc-badge--streaming {
  background: color-mix(in srgb, var(--gocode-accent) 15%, transparent);
  color: var(--gocode-accent);
}

.gc-badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: pulse 1.5s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

@media (prefers-reduced-motion: reduce) {
  .gc-badge-dot {
    animation: none;
  }
}
</style>
