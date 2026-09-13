<script setup lang="ts">
import { GcButton } from '@runne/product/shared/ui'
import { onBeforeUnmount, ref, watch } from 'vue'
import { getCanonicalWorkspace } from '@/entities/project'
import { RetryableWorkspaceOpen, selectAndOpenExistingWorkspace } from '@/features/open-local-project'
import { translate } from '@/shared/i18n'

const props = defineProps<{
  workspaceId: string
  viewGeneration: number
  disabled: boolean
  pending: RetryableWorkspaceOpen | null
}>()
const emit = defineEmits<{
  connected: [workspaceId: string, viewGeneration: number]
  retryable: [error: RetryableWorkspaceOpen, workspaceId: string, viewGeneration: number]
  failed: [workspaceId: string, viewGeneration: number]
}>()
const busy = ref(false)
const failed = ref(false)
let mounted = true
let operationSequence = 0
onBeforeUnmount(() => { mounted = false; operationSequence += 1 })
watch(() => [props.workspaceId, props.viewGeneration], () => {
  operationSequence += 1
  failed.value = false
})

async function connect(): Promise<void> {
  if (busy.value || props.disabled) return
  const workspaceId = props.workspaceId
  const viewGeneration = props.viewGeneration
  const sequence = ++operationSequence
  const current = () => mounted
    && sequence === operationSequence
    && props.workspaceId === workspaceId
    && props.viewGeneration === viewGeneration
    && !props.disabled
  busy.value = true
  failed.value = false
  try {
    if (props.pending !== null) {
      await props.pending.retry()
      if (current()) emit('connected', workspaceId, viewGeneration)
      return
    }
    const snapshot = await getCanonicalWorkspace(workspaceId)
    if (!current()) return
    const result = await selectAndOpenExistingWorkspace(workspaceId, snapshot.version)
    if (current() && result !== null) emit('connected', workspaceId, viewGeneration)
  }
  catch (error) {
    if (!current()) return
    if (error instanceof RetryableWorkspaceOpen) emit('retryable', error, workspaceId, viewGeneration)
    else { failed.value = true; emit('failed', workspaceId, viewGeneration) }
  }
  finally {
    if (mounted && sequence === operationSequence) busy.value = false
  }
}
</script>

<template>
  <div>
    <GcButton
      :disabled="disabled || busy"
      @click="connect"
    >
      {{ translate(busy ? 'openProject.opening' : pending ? 'settings.retry' : 'openProject.chooseFolderAction') }}
    </GcButton>
    <p
      v-if="failed"
      role="alert"
    >
      {{ translate('openProject.openFailed') }}
    </p>
  </div>
</template>
