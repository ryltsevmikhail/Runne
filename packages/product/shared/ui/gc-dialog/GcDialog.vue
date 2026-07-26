<script setup lang="ts">
withDefaults(
  defineProps<{
    open: boolean
    title: string
    description?: string
    confirmLabel?: string
    cancelLabel?: string
    danger?: boolean
  }>(),
  {
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    danger: false,
  },
)

const emit = defineEmits<{
  confirm: []
  cancel: []
  'update:open': [value: boolean]
}>()

function close() {
  emit('update:open', false)
  emit('cancel')
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    close()
  }
}
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="gc-dialog-overlay"
      @click="close"
      @keydown="onKeydown"
    >
      <div
        class="gc-dialog"
        role="dialog"
        aria-modal="true"
        @click.stop
      >
        <div class="gc-dialog-header">
          <h2 class="gc-dialog-title">{{ title }}</h2>
          <p v-if="description || $slots.default" class="gc-dialog-description">
            {{ description }}
            <slot />
          </p>
        </div>
        <div class="gc-dialog-footer">
          <button
            class="gc-dialog-btn gc-dialog-btn--cancel"
            @click="close"
          >
            {{ cancelLabel }}
          </button>
          <button
            :class="['gc-dialog-btn', { 'gc-dialog-btn--danger': danger }]"
            @click="emit('confirm')"
          >
            {{ confirmLabel }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.gc-dialog-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
}

.gc-dialog {
  background: var(--gocode-surface-raised);
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-lg);
  padding: var(--gocode-space-xl);
  max-width: 440px;
  width: calc(100% - var(--gocode-space-2xl));
  font-family: var(--gocode-font-ui);
  color: var(--gocode-text-primary);
}

.gc-dialog-header {
  margin-bottom: var(--gocode-space-xl);
}

.gc-dialog-title {
  margin: 0 0 var(--gocode-space-sm);
  font-size: 18px;
  font-weight: 600;
  color: var(--gocode-text-primary);
}

.gc-dialog-description {
  margin: 0;
  font-size: 14px;
  color: var(--gocode-text-secondary);
  line-height: 1.5;
}

.gc-dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--gocode-space-sm);
}

.gc-dialog-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 8px 16px;
  border-radius: var(--gocode-radius-md);
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
  transition: background var(--gocode-motion-fast) ease,
              border-color var(--gocode-motion-fast) ease,
              color var(--gocode-motion-fast) ease;
  background: var(--gocode-accent);
  color: var(--gocode-text-on-accent);
}

.gc-dialog-btn:hover {
  filter: brightness(1.08);
}

.gc-dialog-btn--cancel {
  background: transparent;
  color: var(--gocode-text-secondary);
}

.gc-dialog-btn--cancel:hover {
  background: var(--gocode-surface);
  border-color: var(--gocode-border);
  color: var(--gocode-text-primary);
}

.gc-dialog-btn--danger {
  background: transparent;
  color: var(--gocode-error-coral);
  border-color: var(--gocode-error-coral);
}

.gc-dialog-btn--danger:hover {
  background: color-mix(in srgb, var(--gocode-error-coral) 10%, transparent);
}
</style>
