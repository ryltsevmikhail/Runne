<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { AttentionQueue } from '@runne/product/attention-queue'

import { acquireRendererGeneration } from '@/entities/project'
import { decideApproval, listPendingApprovals, type ApprovalDecision, type ApprovalSummary } from '@/entities/approval'
import { getManagedAttentionSnapshot } from '@/entities/task-run'
import type { ManagedAttentionSnapshot } from '@/entities/task-run'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate } from '@/shared/i18n'

const props = withDefaults(defineProps<{
  runtimeReady?: boolean
  load?: () => Promise<readonly ApprovalSummary[]>
  loadAttention?: typeof getManagedAttentionSnapshot
  acquireGeneration?: () => Promise<number>
  decide?: (approval: ApprovalSummary, decision: ApprovalDecision, rendererGeneration: number) => Promise<{ readonly approvalId: string }>
}>(), { load: listPendingApprovals })
const runtimeSession = tryUseRuntimeSession()
const runtimeLive = computed(() => props.runtimeReady ?? (runtimeSession?.snapshot.value.status === 'live'))
const approvals = ref<readonly ApprovalSummary[]>([])
const attention = ref<ManagedAttentionSnapshot | null>(null)
const loading = ref(true)
const unavailable = ref(false)
const attentionUnavailable = ref(false)
let inboxRequest = 0
let approvalRequest = 0
const decisionId = ref<string | null>(null)
const decisionFailed = ref(false)

async function decideItem(approval: ApprovalSummary, decision: ApprovalDecision) {
  if (!runtimeLive.value || approval.state !== 'pending' || decisionId.value !== null) return
  const request = approvalRequest
  decisionId.value = approval.approvalId
  decisionFailed.value = false
  try {
    const generation = await (props.acquireGeneration ?? acquireRendererGeneration)()
    if (!runtimeLive.value || request !== approvalRequest) return
    const acknowledgement = await (props.decide ?? decideApproval)(approval, decision, generation)
    if (runtimeLive.value && request === approvalRequest) {
      approvals.value = approvals.value.filter(item => item.approvalId !== acknowledgement.approvalId)
      await loadInbox()
    }
  } catch {
    if (request === approvalRequest) decisionFailed.value = true
  } finally {
    if (request === approvalRequest) decisionId.value = null
  }
}

function decideById(approvalId: string, decision: ApprovalDecision) {
  const approval = approvals.value.find(item => item.approvalId === approvalId)
  if (approval !== undefined) void decideItem(approval, decision)
}

async function loadInbox() {
  const request = ++inboxRequest
  attention.value = null
  if (!runtimeLive.value) { attentionUnavailable.value = true; return }
  try {
    const next = await (props.loadAttention ?? getManagedAttentionSnapshot)()
    if (request === inboxRequest && runtimeLive.value) { attention.value = next; attentionUnavailable.value = false }
  }
  catch { if (request === inboxRequest) attentionUnavailable.value = true }
}
async function loadApprovals() {
  const request = ++approvalRequest
  decisionFailed.value = false
  if (!runtimeLive.value) { approvals.value = []; unavailable.value = true; loading.value = false; return }
  loading.value = true
  try {
    const next = await props.load()
    if (request === approvalRequest && runtimeLive.value) { approvals.value = next; unavailable.value = false }
  } catch { if (request === approvalRequest) unavailable.value = true }
  finally { if (request === approvalRequest) loading.value = false }
}
onMounted(() => { void loadApprovals(); void loadInbox() })
watch(runtimeLive, live => {
  approvalRequest += 1; inboxRequest += 1; attention.value = null
  if (live) { void loadApprovals(); void loadInbox() }
  else {
    decisionId.value = null
    decisionFailed.value = false
    approvals.value = []; unavailable.value = true; loading.value = false; attentionUnavailable.value = true
  }
})
onBeforeUnmount(() => { inboxRequest += 1; approvalRequest += 1 })
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
    <AttentionQueue v-else :items="approvals" :disabled="unavailable || !runtimeLive" :pending-id="decisionId" @decide="decideById" />
    <section aria-labelledby="runtime-attention-title">
      <h2 id="runtime-attention-title">{{ translate('approvals.attentionQueue') }}</h2>
      <p v-if="attentionUnavailable || attention?.status === 'unavailable'" role="status">{{ translate('attention.snapshotUnavailable') }}</p>
      <p v-if="attention?.status === 'available' && !attention.complete" role="status">{{ translate('attention.snapshotUnavailable') }}</p>
      <ul v-if="attention?.status === 'available' && attention.items.length">
        <li v-for="(item, index) in attention.items" :key="`${item.kind}:${item.taskRunId ?? item.approvalId ?? index}`">
          <template v-if="item.kind === 'effective_authority_unavailable'">{{ translate('taskComposer.authorityUnavailable') }}</template>
          <template v-else-if="item.kind === 'runtime_unavailable'">{{ translate('attention.snapshotUnavailable') }}</template>
          <template v-else-if="item.kind === 'effects_unavailable'">{{ translate('attention.effectsUnavailable') }}</template>
          <RouterLink v-else-if="item.taskRunId" :to="{ name: 'task-run', params: { taskRunId: item.taskRunId } }">
            {{ translate(item.kind === 'approval' ? 'attention.approval' : item.kind === 'failed' ? 'attention.failed' : 'attention.uncertain') }} · {{ item.taskRunId }}
          </RouterLink>
        </li>
      </ul>
    </section>
  </section>
</template>
