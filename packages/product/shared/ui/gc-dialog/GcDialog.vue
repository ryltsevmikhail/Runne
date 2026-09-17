<script setup lang="ts">
import { nextTick, ref, useId, watch } from 'vue'

const props = withDefaults(
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

const dialog = ref<HTMLElement | null>(null)
const cancelButton = ref<HTMLButtonElement | null>(null)
const titleId = useId()
const descriptionId = useId()

watch(() => props.open, async (open) => {
  if (open) {
    await nextTick()
    cancelButton.value?.focus()
  }
}, { immediate: true })

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
        ref="dialog"
        class="gc-dialog"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="titleId"
        :aria-describedby="description || $slots.default ? descriptionId : undefined"
        tabindex="-1"
        @click.stop
      >
        <div class="gc-dialog-header">
          <h2
            :id="titleId"
            class="gc-dialog-title"
          >
            {{ title }}
          </h2>
          <p
            v-if="description || $slots.default"
            :id="descriptionId"
            class="gc-dialog-description"
          >
            {{ description }}
            <slot />
          </p>
        </div>
        <div class="gc-dialog-footer">
          <button
            ref="cancelButton"
            class="gc-dialog-btn gc-dialog-btn--cancel"
            type="button"
            @click="close"
          >
            {{ cancelLabel }}
          </button>
          <button
            :class="['gc-dialog-btn', { 'gc-dialog-btn--danger': danger }]"
            type="button"
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
  background: var(--runne-surface-raised);
  border: 1px solid var(--runne-border);
  border-radius: var(--runne-radius-lg);
  padding: var(--runne-space-xl);
  max-width: 440px;
  width: calc(100% - var(--runne-space-2xl));
  font-family: var(--runne-font-ui);
  color: var(--runne-text-primary);
}

.gc-dialog-header {
  margin-bottom: var(--runne-space-xl);
}

.gc-dialog-title {
  margin: 0 0 var(--runne-space-sm);
  font-size: 18px;
  font-weight: 600;
  color: var(--runne-text-primary);
}

.gc-dialog-description {
  margin: 0;
  font-size: 14px;
  color: var(--runne-text-secondary);
  line-height: 1.5;
}

.gc-dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--runne-space-sm);
}

.gc-dialog-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 8px 16px;
  border-radius: var(--runne-radius-md);
  font-family: var(--runne-font-ui);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
  transition: background var(--runne-motion-fast) ease,
              border-color var(--runne-motion-fast) ease,
              color var(--runne-motion-fast) ease;
  background: var(--runne-accent);
  color: var(--runne-text-on-accent);
}

.gc-dialog-btn:hover {
  filter: brightness(1.08);
}

.gc-dialog-btn--cancel {
  background: transparent;
  color: var(--runne-text-secondary);
}

.gc-dialog-btn--cancel:hover {
  background: var(--runne-surface);
  border-color: var(--runne-border);
  color: var(--runne-text-primary);
}

.gc-dialog-btn--danger {
  background: transparent;
  color: var(--runne-error-coral);
  border-color: var(--runne-error-coral);
}

.gc-dialog-btn--danger:hover {
  background: color-mix(in srgb, var(--runne-error-coral) 10%, transparent);
}
</style>
