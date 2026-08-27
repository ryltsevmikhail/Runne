<script setup lang="ts">
import { GcButton } from '../../shared/ui'

defineProps<{
  disabled: boolean
  pending: boolean
}>()
const emit = defineEmits<{ decide: [decision: 'approve' | 'deny'] }>()
</script>

<template>
  <div class="respond-to-approval">
    <GcButton
      data-approval-action="approve"
      :disabled="disabled || pending"
      @click="emit('decide', 'approve')"
    >
      Approve
    </GcButton>
    <GcButton
      data-approval-action="deny"
      variant="secondary"
      :disabled="disabled || pending"
      @click="emit('decide', 'deny')"
    >
      Deny
    </GcButton>
  </div>
</template>

<style scoped>
.respond-to-approval { display: flex; flex-wrap: wrap; gap: var(--runne-space-sm); }
</style>
