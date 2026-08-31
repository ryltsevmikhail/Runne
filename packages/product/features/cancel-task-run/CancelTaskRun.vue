<script setup lang="ts">
import { GcButton } from '../../shared/ui'

defineProps<{
  disabled: boolean
  pending: boolean
}>()
const emit = defineEmits<{ request: [] }>()
</script>

<template>
  <GcButton
    data-task-run-action="cancel"
    variant="secondary"
    :disabled="disabled || pending"
    @click="emit('request')"
  >
    {{ pending ? 'Requesting cancellation…' : 'Request cancellation' }}
  </GcButton>
</template>
