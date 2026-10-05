<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { GcButton } from '@runne/product/shared/ui'
import { translate } from '@/shared/i18n'
import { useTaskComposer } from '../model/use-task-composer'
import type { DraftApi } from '../model/draft-session'
import { prepareManagedTaskRun, recoverManagedTaskRun, startManagedTaskRun } from '@/entities/task-run/api/managed-task-run'

const props = withDefaults(defineProps<{
  projectId: string
  workspaceId: string
  disabled?: boolean
  prepare?: typeof prepareManagedTaskRun | undefined
  start?: typeof startManagedTaskRun | undefined
  recover?: typeof recoverManagedTaskRun | undefined
  storage?: Storage | undefined
  draftApi?: DraftApi | undefined
}>(), { disabled: false })
const {
  draft, status, recoveryMessage, recoveryStorageUnavailable, operationFailed, pending, busy,
  draftCleanupReady, draftVisible, promptTooLong, submitDisabled, textareaDisabled, setPrompt, reconcileDraft,
  submitPrompt, checkStatus, startAnotherTask, retryDraftCleanup,
} = useTaskComposer(props)
function retryDraftSave(): void { void draft.retry().catch(() => undefined) }
const policyCopy = computed(() => {
  if (draft.view.policy === 'protected_restart') return translate('taskComposer.draftPolicyProtected')
  if (draft.view.policy === 'memory_only') return translate('taskComposer.draftPolicyMemory')
  if (draft.view.policy === 'unknown') return translate('taskComposer.draftPolicyPending')
  return translate('taskComposer.draftPolicyUnavailable')
})
function onPromptInput(event: Event): void {
  const target = event.currentTarget
  if (target instanceof HTMLTextAreaElement) setPrompt(target.value)
}
</script>

<template>
  <form class="task-composer" aria-labelledby="task-composer-title" @submit.prevent="submitPrompt">
    <h2 id="task-composer-title">{{ translate('taskComposer.title') }}</h2>
    <label for="managed-task-prompt">{{ translate('taskComposer.promptLabel') }}</label>
    <textarea id="managed-task-prompt" :value="draftVisible ? draft.view.prompt : ''" :disabled="textareaDisabled" :placeholder="translate('taskComposer.placeholder')" rows="3" @input="onPromptInput" />
    <small v-if="draftVisible">{{ policyCopy }}</small>
    <p v-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'loading'" role="status">{{ translate('taskComposer.draftLoading') }}</p>
    <p v-else-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'saving'" role="status">{{ translate('taskComposer.draftSaving') }}</p>
    <p v-else-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'saved'" role="status">{{ translate('taskComposer.draftSaved') }}</p>
    <p v-else-if="draftVisible && draft.view.policy === 'memory_only' && draft.view.status === 'memory'" role="status">{{ translate('taskComposer.draftInMemory') }}</p>
    <p v-else-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'unsaved'" role="status">{{ translate('taskComposer.draftUnsaved') }}</p>
    <p v-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'error' && draft.view.error === 'capacity'" role="alert">{{ translate('taskComposer.draftCapacity') }}</p>
    <p v-else-if="draftVisible && draft.view.policy !== 'unknown' && (draft.view.status === 'error' || draft.view.status === 'unavailable')" role="alert">{{ translate('taskComposer.draftSaveFailed') }}</p>
    <p v-else-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'conflict'" role="alert">{{ translate('taskComposer.draftConflict') }}</p>
    <GcButton v-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'conflict'" type="button" :disabled="busy" @click="reconcileDraft('keep_local')">{{ translate('taskComposer.draftKeepLocal') }}</GcButton>
    <GcButton v-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'conflict'" type="button" :disabled="busy" @click="reconcileDraft('use_saved')">{{ translate('taskComposer.draftUseSaved') }}</GcButton>
    <GcButton v-if="draftVisible && draft.view.policy !== 'unknown' && draft.view.status === 'error' && !(status === 'accepted' && !draftCleanupReady)" type="button" :disabled="busy" @click="retryDraftSave">{{ translate('taskComposer.draftRetry') }}</GcButton>
    <dl class="task-composer__authority" aria-label="Effective runtime authority">
      <div><dt>{{ translate('taskComposer.provider') }}</dt><dd>{{ translate('taskComposer.valueUnavailable') }}</dd></div>
      <div><dt>{{ translate('taskComposer.model') }}</dt><dd>{{ translate('taskComposer.valueUnavailable') }}</dd></div>
      <div><dt>{{ translate('taskComposer.policy') }}</dt><dd>{{ translate('taskComposer.valueUnavailable') }}</dd></div>
    </dl>
    <p role="status">{{ translate('taskComposer.authorityUnavailable') }}</p>
    <p v-if="disabled || status === 'waiting'" role="status">{{ translate('taskComposer.waitingRuntime') }}</p>
    <p v-else-if="status === 'preparing'" role="status">{{ translate('taskComposer.preparing') }}</p>
    <p v-else-if="status === 'unavailable'" role="status">{{ translate('taskComposer.startUnavailable') }}</p>
    <p v-else-if="status === 'uncertain'" role="alert">{{ translate('taskComposer.uncertain') }} {{ recoveryMessage === 'uncertain' ? translate('taskComposer.pending') : '' }}</p>
    <p v-else-if="status === 'accepted'" role="status">{{ translate('taskComposer.accepted') }}</p>
    <p v-if="status === 'accepted' && recoveryMessage === 'newer_draft'" role="status">{{ translate('taskComposer.draftNewerPreserved') }}</p>
    <p v-if="status === 'accepted' && !draftCleanupReady" role="alert">{{ translate('taskComposer.draftCleanupPending') }}</p>
    <RouterLink v-if="status === 'accepted' && pending?.acceptedTaskRunId" :to="{ name: 'task-run', params: { taskRunId: pending.acceptedTaskRunId } }">{{ translate('taskComposer.openAccepted') }}</RouterLink>
    <p v-if="recoveryStorageUnavailable" role="alert">{{ translate('taskComposer.storageUnavailable') }}</p>
    <p v-if="operationFailed" role="alert">{{ translate('taskComposer.failed') }}</p>
    <p v-if="draftVisible && promptTooLong" role="alert">{{ translate('taskComposer.promptTooLong') }}</p>
    <GcButton v-if="status === 'accepted' && !draftCleanupReady && !disabled" type="button" :disabled="busy" @click="retryDraftCleanup">{{ translate('taskComposer.draftRetryCleanup') }}</GcButton>
    <GcButton v-else-if="status === 'accepted' && draftCleanupReady && !disabled" type="button" @click="startAnotherTask">{{ translate('taskComposer.newTask') }}</GcButton>
    <GcButton v-else-if="status === 'uncertain' && !disabled" type="button" :disabled="busy" @click="checkStatus">{{ translate('taskComposer.checkStatus') }}</GcButton>
    <GcButton v-else type="submit" :disabled="submitDisabled" @click="submitPrompt">{{ status === 'starting' ? translate('taskComposer.starting') : translate('taskComposer.start') }}</GcButton>
  </form>
</template>

<style scoped>
.task-composer { display: grid; gap: 0.55rem; padding: 0.9rem 0; border-bottom: 1px solid var(--gc-border, #343a40); }
.task-composer h2 { margin: 0; font-size: 0.95rem; }
.task-composer label, .task-composer dt { font-size: 0.82rem; font-weight: 600; }
.task-composer textarea { width: 100%; resize: vertical; padding: 0.65rem; color: inherit; background: var(--gc-surface, transparent); border: 1px solid var(--gc-border, #555); border-radius: 0.4rem; font: inherit; }
.task-composer p { margin: 0; font-size: 0.85rem; }
.task-composer [role="alert"] { color: var(--gc-danger, #c33); }
.task-composer__authority { display: flex; gap: 1rem; margin: 0; }
.task-composer__authority div { display: flex; gap: 0.35rem; }
.task-composer__authority dd { margin: 0; }
</style>
