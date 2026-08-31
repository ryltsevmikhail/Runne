<script setup lang="ts">
import { ref, watch } from 'vue'

import { GcButton, GcTextarea } from '../../shared/ui'

const props = withDefaults(defineProps<{
  modelValue?: string
  disabled: boolean
  pending: boolean
}>(), { modelValue: '' })
const emit = defineEmits<{
  submit: [text: string]
  'update:modelValue': [value: string]
}>()
const draft = ref(props.modelValue)

watch(() => props.modelValue, value => { draft.value = value })

function update(value: string) {
  draft.value = value
  emit('update:modelValue', value)
}

function submit() {
  const text = draft.value.trim()
  if (props.disabled || props.pending || text.length === 0) return
  emit('submit', text)
  draft.value = ''
  emit('update:modelValue', '')
}
</script>

<template>
  <form class="submit-prompt" @submit.prevent="submit">
    <GcTextarea
      :model-value="draft"
      label="Message"
      placeholder="Describe the next task"
      :rows="3"
      :state="disabled ? 'disabled' : 'default'"
      @update:modelValue="update"
    />
    <GcButton :disabled="disabled || pending || draft.trim().length === 0" type="submit">
      {{ pending ? 'Running…' : 'Send' }}
    </GcButton>
  </form>
</template>

<style scoped>
.submit-prompt {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: var(--runne-space-md);
  padding: var(--runne-space-md) var(--runne-space-lg);
  border-top: 1px solid var(--runne-border);
  background: var(--runne-surface);
}

@media (max-width: 640px) {
  .submit-prompt { grid-template-columns: 1fr; }
}
</style>
