<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { listPendingApprovals, type ApprovalSummary } from '@/entities/approval'
import { translate } from '@/shared/i18n'

const props = withDefaults(defineProps<{
  load?: () => Promise<readonly ApprovalSummary[]>
}>(), { load: listPendingApprovals })
const approvals = ref<readonly ApprovalSummary[]>([])
const loading = ref(true)
const unavailable = ref(false)

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
    <p v-else-if="approvals.length === 0">{{ translate('approvals.empty') }}</p>
    <ul v-else class="approval-list">
      <li v-for="approval in approvals" :key="approval.approvalId" class="approval-card">
        <div>
          <strong>{{ approval.action }}</strong>
          <span>{{ approval.resource }}</span>
          <small>{{ approval.riskSummary }}</small>
        </div>
        <span class="approval-state">{{ approval.state }}</span>
      </li>
    </ul>
  </section>
</template>
