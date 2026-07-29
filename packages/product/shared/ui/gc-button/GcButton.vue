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
  gap: var(--gocode-space-sm);
  font-family: var(--gocode-font-ui);
  font-weight: 500;
  border-radius: var(--gocode-radius-md);
  cursor: pointer;
  transition: background var(--gocode-motion-fast) ease,
              border-color var(--gocode-motion-fast) ease,
              color var(--gocode-motion-fast) ease;
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
  background: var(--gocode-accent);
  color: var(--gocode-text-on-accent);
  border-color: var(--gocode-accent);
}
.gc-button--primary:hover {
  filter: brightness(1.08);
}

/* Ghost: transparent, subtle text, border on hover */
.gc-button--ghost {
  background: transparent;
  color: var(--gocode-text-secondary);
}
.gc-button--ghost:hover {
  background: var(--gocode-surface);
  border-color: var(--gocode-border);
  color: var(--gocode-text-primary);
}

/* Secondary: raised surface */
.gc-button--secondary {
  background: var(--gocode-surface-raised);
  color: var(--gocode-text-primary);
  border-color: var(--gocode-border);
}
.gc-button--secondary:hover {
  border-color: var(--gocode-text-secondary);
}

/* Disabled */
.gc-button--disabled {
  opacity: 0.4;
  pointer-events: none;
  cursor: not-allowed;
  background: var(--gocode-surface);
  color: var(--gocode-text-secondary);
  border-color: var(--gocode-border);
}

/* Delete/danger */
.gc-button--delete {
  background: transparent;
  color: var(--gocode-error-coral);
  border-color: var(--gocode-error-coral);
}
.gc-button--delete:hover {
  background: color-mix(in srgb, var(--gocode-error-coral) 10%, transparent);
}
</style>
