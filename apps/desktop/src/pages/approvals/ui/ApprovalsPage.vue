<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { AttentionQueue } from '@runne/product/attention-queue'

import { acquireRendererGeneration } from '@/entities/project'
import { decideApproval, listPendingApprovals, type ApprovalDecision, type ApprovalSummary } from '@/entities/approval'
import { translate } from '@/shared/i18n'

const props = withDefaults(defineProps<{
  load?: () => Promise<readonly ApprovalSummary[]>
  acquireGeneration?: () => Promise<number>
  decide?: (approval: ApprovalSummary, decision: ApprovalDecision, rendererGeneration: number) => Promise<{ readonly approvalId: string }>
}>(), { load: listPendingApprovals })
const approvals = ref<readonly ApprovalSummary[]>([])
const loading = ref(true)
const unavailable = ref(false)
const decisionId = ref<string | null>(null)
const decisionFailed = ref(false)

async function decideItem(approval: ApprovalSummary, decision: ApprovalDecision) {
  if (approval.state !== 'pending' || decisionId.value !== null) return
  decisionId.value = approval.approvalId
  decisionFailed.value = false
  try {
    const generation = await (props.acquireGeneration ?? acquireRendererGeneration)()
    const acknowledgement = await (props.decide ?? decideApproval)(approval, decision, generation)
    approvals.value = approvals.value.filter(item => item.approvalId !== acknowledgement.approvalId)
  } catch {
    decisionFailed.value = true
  } finally {
    decisionId.value = null
  }
}

function decideById(approvalId: string, decision: ApprovalDecision) {
  const approval = approvals.value.find(item => item.approvalId === approvalId)
  if (approval !== undefined) void decideItem(approval, decision)
}

onMounted(async () => {
  try { approvals.value = await props.load() }
  catch { unavailable.value = true }
  finally { loading.value = false }
})
</script>

<template>
  <section class="page-shell" aria-labelledby="approvals-title">
    <header class="page-header">
      <p class="eyebrow">{{ translate('approvals.attentionQueue') }}</p>
      <h1 id="approvals-title">{{ translate('approvals.title') }}</h1>
      <p>{{ translate('approvals.description') }}</p>
    </header>
    <p v-if="loading" aria-live="polite">{{ translate('approvals.loading') }}</p>
    <p v-else-if="unavailable" role="alert">{{ translate('approvals.unavailable') }}</p>
    <p v-else-if="decisionFailed" role="alert">{{ translate('approvals.decisionFailed') }}</p>
    <p v-else-if="approvals.length === 0">{{ translate('approvals.empty') }}</p>
    <AttentionQueue
      v-else
      :items="approvals"
      :disabled="unavailable"
      :pending-id="decisionId"
      @decide="decideById"
    />
  </section>
</template>
