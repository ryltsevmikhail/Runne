<script setup lang="ts">
defineProps<{
  variant?: 'primary' | 'ghost' | 'secondary' | 'disabled' | 'delete'
  size?: 'sm' | 'md'
  disabled?: boolean
}>()

defineEmits<{
  click: [e: MouseEvent]
}>()
</script>

<template>
  <button
    type="button"
    :class="['gc-button', `gc-button--${variant ?? 'primary'}`, `gc-button--${size ?? 'md'}`]"
    :disabled="disabled || variant === 'disabled'"
    @click="$emit('click', $event)"
  >
    <slot />
  </button>
</template>

<style scoped>
.gc-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--runne-space-sm);
  font-family: var(--runne-font-ui);
  font-weight: 500;
  border-radius: var(--runne-radius-md);
  cursor: pointer;
  transition: background var(--runne-motion-fast) ease,
              border-color var(--runne-motion-fast) ease,
              color var(--runne-motion-fast) ease;
  border: 1px solid transparent;
  user-select: none;
  white-space: nowrap;
}

.gc-button--md {
  padding: 8px 16px;
  font-size: 14px;
  line-height: 1.4;
}

.gc-button--sm {
  padding: 4px 12px;
  font-size: 13px;
  line-height: 1.3;
}

/* Primary: accent fill, Graphite text (Pen authority) */
.gc-button--primary {
  background: var(--runne-accent);
  color: var(--runne-text-on-accent);
  border-color: var(--runne-accent);
}
.gc-button--primary:hover {
  filter: brightness(1.08);
}

/* Ghost: transparent, subtle text, border on hover */
.gc-button--ghost {
  background: transparent;
  color: var(--runne-text-secondary);
}
.gc-button--ghost:hover {
  background: var(--runne-surface);
  border-color: var(--runne-border);
  color: var(--runne-text-primary);
}

/* Secondary: raised surface */
.gc-button--secondary {
  background: var(--runne-surface-raised);
  color: var(--runne-text-primary);
  border-color: var(--runne-border);
}
.gc-button--secondary:hover {
  border-color: var(--runne-text-secondary);
}

/* Disabled */
.gc-button--disabled {
  opacity: 0.4;
  pointer-events: none;
  cursor: not-allowed;
  background: var(--runne-surface);
  color: var(--runne-text-secondary);
  border-color: var(--runne-border);
}

/* Delete/danger */
.gc-button--delete {
  background: transparent;
  color: var(--runne-error-coral);
  border-color: var(--runne-error-coral);
}
.gc-button--delete:hover {
  background: color-mix(in srgb, var(--runne-error-coral) 10%, transparent);
}
</style>
