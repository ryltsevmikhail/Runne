<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { GcAlert, GcButton } from '@runne/product/shared/ui'
import { supersedeUnknownTaskRun, type SuccessorEligibility } from '@/entities/task-run'
import { translate } from '@/shared/i18n'

const props = defineProps<{
  taskRunId: string
  expectedVersion: number
  eligibility: SuccessorEligibility
  runtimeLive: boolean
}>()
const emit = defineEmits<{ created: [value: { predecessorTaskRunId: string, predecessorVersion: number, taskRunId: string }] }>()
const acknowledged = ref(false)
const pending = ref(false)
const indeterminate = ref(false)
const createdId = ref<string | null>(null)
let operationGeneration = 0
let mounted = true

watch(() => [props.taskRunId, props.expectedVersion, props.eligibility] as const, () => {
  operationGeneration += 1
  acknowledged.value = false
  pending.value = false
  indeterminate.value = false
  createdId.value = null
})
watch(() => props.runtimeLive, live => {
  acknowledged.value = false
  if (!live && pending.value) {
    operationGeneration += 1
    pending.value = false
    indeterminate.value = true
  }
})
onBeforeUnmount(() => { mounted = false; operationGeneration += 1 })

async function createSuccessor() {
  if (!acknowledged.value || !props.runtimeLive
      || !['eligible', 'requires_duplicate_effect_acknowledgment'].includes(props.eligibility)
      || pending.value || indeterminate.value) return
  pending.value = true
  const predecessorTaskRunId = props.taskRunId
  const expectedVersion = props.expectedVersion
  const eligibility = props.eligibility
  const generation = operationGeneration
  try {
    const result = await supersedeUnknownTaskRun(predecessorTaskRunId, expectedVersion, {
      acknowledgeDuplicateExecutionAndCost: true,
    })
    if (!mounted || generation !== operationGeneration || !props.runtimeLive
        || props.taskRunId !== predecessorTaskRunId || props.expectedVersion !== expectedVersion
        || props.eligibility !== eligibility) return
    createdId.value = result.taskRunId
    acknowledged.value = false
    emit('created', { predecessorTaskRunId, predecessorVersion: result.predecessorVersion, taskRunId: result.taskRunId })
  } catch {
    // Keep this view from creating a fresh command after an uncertain acknowledgment.
    if (mounted && generation === operationGeneration && props.taskRunId === predecessorTaskRunId) {
      indeterminate.value = true
    }
  } finally {
    if (mounted && generation === operationGeneration) pending.value = false
  }
}
</script>

<template>
  <section v-if="['eligible', 'requires_duplicate_effect_acknowledgment'].includes(eligibility)" class="task-run-successor" aria-live="polite">
    <GcAlert level="warning" :title="translate('taskRun.effects.successorRiskTitle')">
      {{ translate('taskRun.effects.successorRiskDetail') }}
    </GcAlert>
    <label>
      <input v-model="acknowledged" type="checkbox" :disabled="pending || indeterminate">
      {{ translate('taskRun.effects.successorAcknowledge') }}
    </label>
    <GcButton variant="secondary" :disabled="!acknowledged || pending || indeterminate || !runtimeLive" @click="createSuccessor">
      {{ pending ? translate('taskRun.effects.successorCreating') : translate('taskRun.effects.successorCreate') }}
    </GcButton>
    <p v-if="createdId !== null" role="status">
      {{ translate('taskRun.effects.successorCreated', { taskRunId: createdId }) }}
    </p>
    <GcAlert v-if="indeterminate" level="warning" :title="translate('taskRun.effects.successorIndeterminateTitle')">
      {{ translate('taskRun.effects.successorIndeterminateDetail') }}
    </GcAlert>
  </section>
</template>
