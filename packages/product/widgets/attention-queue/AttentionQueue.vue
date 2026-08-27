<script setup lang="ts">
import { RespondToApproval } from '../../features/respond-to-approval'

export interface AttentionQueueItem {
  readonly approvalId: string
  readonly action: string
  readonly resource: string
  readonly riskSummary: string
  readonly state: 'pending' | 'approved' | 'denied' | 'expired' | 'cancelled'
}

defineProps<{
  items: readonly AttentionQueueItem[]
  disabled: boolean
  pendingId: string | null
}>()
const emit = defineEmits<{ decide: [approvalId: string, decision: 'approve' | 'deny'] }>()
</script>

<template>
  <ul class="attention-queue" aria-label="Approvals requiring attention">
    <li v-for="item in items" :key="item.approvalId" class="attention-queue__item">
      <div>
        <strong>{{ item.action }}</strong>
        <span>{{ item.resource }}</span>
        <small>{{ item.riskSummary }}</small>
      </div>
      <span class="attention-queue__state">{{ item.state }}</span>
      <RespondToApproval
        v-if="item.state === 'pending'"
        :disabled="disabled"
        :pending="pendingId === item.approvalId"
        @decide="decision => emit('decide', item.approvalId, decision)"
      />
    </li>
  </ul>
</template>

<style scoped>
.attention-queue { display: grid; gap: var(--runne-space-md); margin: 0; padding: 0; list-style: none; }
.attention-queue__item { display: grid; gap: var(--runne-space-sm); padding: var(--runne-space-lg); border: 1px solid var(--runne-border); border-radius: var(--runne-radius-md); background: var(--runne-surface-raised); }
.attention-queue__item span, .attention-queue__item small { display: block; color: var(--runne-ui-muted); overflow-wrap: anywhere; }
.attention-queue__state { text-transform: capitalize; }
</style>
