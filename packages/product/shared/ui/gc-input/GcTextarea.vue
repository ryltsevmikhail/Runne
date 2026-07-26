<script setup lang="ts">
defineProps<{
  modelValue: string
  state?: 'default' | 'disabled' | 'error'
  label?: string
  helper?: string
  placeholder?: string
  rows?: number
}>()

defineEmits<{
  'update:modelValue': [value: string]
}>()
</script>

<template>
  <div :class="['gc-input-wrapper', state && `gc-input-wrapper--${state}`]">
    <label v-if="label" class="gc-input-label">{{ label }}</label>
    <textarea
      :value="modelValue"
      :placeholder="placeholder"
      :disabled="state === 'disabled'"
      :rows="rows ?? 3"
      class="gc-textarea"
      @input="$emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
    />
    <span v-if="helper" :class="['gc-input-helper', state === 'error' && 'gc-input-helper--error']">
      {{ helper }}
    </span>
  </div>
</template>

<style scoped>
.gc-textarea {
  width: 100%;
  padding: 8px 12px;
  background: var(--gocode-surface);
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-md);
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  color: var(--gocode-text-primary);
  outline: none;
  resize: vertical;
  transition: border-color var(--gocode-motion-fast) ease;
}

.gc-textarea:focus {
  border-color: var(--gocode-accent);
}

.gc-input-wrapper--error .gc-textarea {
  border-color: var(--gocode-error-coral);
}

.gc-input-wrapper--disabled .gc-textarea {
  opacity: 0.5;
  pointer-events: none;
}

.gc-textarea::placeholder {
  color: var(--gocode-ui-subtle);
}
</style>
