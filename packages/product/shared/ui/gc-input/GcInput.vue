<script setup lang="ts">
defineProps<{
  modelValue: string
  state?: 'default' | 'disabled' | 'error' | 'focus'
  label?: string
  helper?: string
  placeholder?: string
  type?: string
}>()

defineEmits<{
  'update:modelValue': [value: string]
}>()
</script>

<template>
  <div :class="['gc-input-wrapper', state && `gc-input-wrapper--${state}`]">
    <label v-if="label" class="gc-input-label">{{ label }}</label>
    <div class="gc-input-field">
      <span v-if="$slots.leading" class="gc-input-icon gc-input-icon--leading">
        <slot name="leading" />
      </span>
      <input
        :type="type ?? 'text'"
        :value="modelValue"
        :placeholder="placeholder"
        :disabled="state === 'disabled'"
        class="gc-input"
        @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
      />
      <span v-if="$slots.trailing" class="gc-input-icon gc-input-icon--trailing">
        <slot name="trailing" />
      </span>
    </div>
    <span v-if="helper" :class="['gc-input-helper', state === 'error' && 'gc-input-helper--error']">
      {{ helper }}
    </span>
  </div>
</template>

<style scoped>
.gc-input-wrapper {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.gc-input-label {
  font-size: 13px;
  font-weight: 500;
  color: var(--gocode-text-primary);
}

.gc-input-field {
  display: flex;
  align-items: center;
  background: var(--gocode-surface);
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-md);
  transition: border-color var(--gocode-motion-fast) ease;
}

.gc-input-wrapper--focus .gc-input-field {
  border-color: var(--gocode-accent);
}

.gc-input-wrapper--error .gc-input-field {
  border-color: var(--gocode-error-coral);
}

.gc-input-wrapper--disabled .gc-input-field {
  opacity: 0.5;
  pointer-events: none;
}

.gc-input {
  flex: 1;
  padding: 8px 12px;
  background: transparent;
  border: none;
  outline: none;
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  color: var(--gocode-text-primary);
}

.gc-input::placeholder {
  color: var(--gocode-ui-subtle);
}

.gc-input:disabled {
  cursor: not-allowed;
}

.gc-input-icon {
  display: flex;
  align-items: center;
  padding: 0 8px;
  color: var(--gocode-ui-muted);
}

.gc-input-helper {
  font-size: 12px;
  color: var(--gocode-ui-muted);
}

.gc-input-helper--error {
  color: var(--gocode-error-coral);
}
</style>
