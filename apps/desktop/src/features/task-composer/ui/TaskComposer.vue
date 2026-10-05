<script setup lang="ts">
import { GcButton } from '@runne/product/shared/ui'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { prepareManagedTaskRun, recoverManagedTaskRun, startManagedTaskRun } from '@/entities/task-run'
import type { ManagedTaskRunPreflight } from '@/entities/task-run'
import { translate } from '@/shared/i18n'
import { clearDraft, clearPendingRun, draftFor, loadPendingRun, savePendingRun, setDraft } from '../model/pending-run'
import type { PendingRunBinding } from '../model/pending-run'

const MAX_PROMPT_BYTES = 64 * 1024
const props = withDefaults(defineProps<{
  projectId: string
  workspaceId: string
  disabled?: boolean
  prepare?: typeof prepareManagedTaskRun | undefined
  start?: typeof startManagedTaskRun | undefined
  recover?: typeof recoverManagedTaskRun | undefined
  storage?: Storage | undefined
}>(), { disabled: false })
const router = useRouter()
const prompt = ref(draftFor(props.workspaceId))
const preflight = ref<ManagedTaskRunPreflight | null>(null)
const status = ref<'waiting' | 'preparing' | 'ready' | 'unavailable' | 'starting' | 'uncertain' | 'accepted'>('waiting')
const recoveryMessage = ref<'not_committed' | 'uncertain' | 'unavailable' | null>(null)
const storageUnavailable = ref(false)
const operationFailed = ref(false)
const scopeOperation = ref(0)
const pending = ref<PendingRunBinding | null>(null)
const localSubmissionToken = ref<string | null>(null)
const promptTooLong = computed(() => new TextEncoder().encode(prompt.value).length > MAX_PROMPT_BYTES)
const submitDisabled = computed(() => props.disabled || status.value !== 'ready' || prompt.value.trim().length === 0 || promptTooLong.value)
const busy = ref(false)

watch(() => props.workspaceId, (workspaceId, previous) => {
  setDraft(previous, prompt.value)
  prompt.value = draftFor(workspaceId)
}, { flush: 'sync' })
watch(prompt, value => {
  if (!props.workspaceId) return
  setDraft(props.workspaceId, value)
}, { flush: 'sync' })
watch([() => props.projectId, () => props.workspaceId, () => props.disabled], () => { void refreshScope() }, { immediate: true })
function onStorage(event: StorageEvent) {
  if (event.key === `runne:managed-task-run:${props.workspaceId}`) void refreshScope()
}
if (typeof window !== 'undefined') window.addEventListener('storage', onStorage)

function isCurrent(operation: number, projectId: string, workspaceId: string): boolean {
  return operation === scopeOperation.value && props.projectId === projectId && props.workspaceId === workspaceId && !props.disabled
}
function store(): Storage { return props.storage ?? localStorage }

async function refreshScope() {
  const operation = ++scopeOperation.value
  const projectId = props.projectId
  const workspaceId = props.workspaceId
  preflight.value = null
  pending.value = null
  busy.value = false
  operationFailed.value = false
  recoveryMessage.value = null
  if (props.disabled) { status.value = 'waiting'; return }
  if (!projectId || !workspaceId) { status.value = 'unavailable'; return }
  let saved
  try { saved = loadPendingRun(workspaceId, store()) }
  catch { storageUnavailable.value = true; status.value = 'uncertain'; return }
  if (saved.status === 'corrupt') { status.value = 'uncertain'; recoveryMessage.value = 'unavailable'; return }
  if (saved.status === 'pending') {
    if (saved.binding.projectId !== projectId) { status.value = 'uncertain'; recoveryMessage.value = 'unavailable'; return }
    pending.value = saved.binding
    if (saved.binding.acceptedTaskRunId !== undefined) {
      if (saved.binding.navigated === true) {
        status.value = 'accepted'
        return
      }
      else { await openAccepted(operation, projectId, workspaceId, saved.binding, saved.binding.acceptedTaskRunId); return }
    } else {
      status.value = 'uncertain'
      await reconcile(operation, projectId, workspaceId, saved.binding)
      return
    }
  }
  status.value = 'preparing'
  try {
    const next = await (props.prepare ?? prepareManagedTaskRun)(projectId, workspaceId)
    if (!isCurrent(operation, projectId, workspaceId)) return
    if (next.projectId !== projectId || next.workspaceId !== workspaceId) throw new Error('Scope mismatch')
    preflight.value = next
    status.value = next.status === 'ready' && next.canStart && next.generation !== null && next.conversationId !== null && next.recoveryToken !== null ? 'ready' : 'unavailable'
  } catch {
    if (isCurrent(operation, projectId, workspaceId)) status.value = 'unavailable'
  }
}

async function reconcile(operation: number, projectId: string, workspaceId: string, binding: PendingRunBinding) {
  if (!isCurrent(operation, projectId, workspaceId)) return
  try {
    const result = await (props.recover ?? recoverManagedTaskRun)(binding.recoveryToken)
    if (operation !== scopeOperation.value || props.workspaceId !== workspaceId || props.projectId !== projectId) return
    if (result.status === 'accepted' && (result.workspaceId !== binding.workspaceId || result.conversationId !== binding.conversationId)) {
      recoveryMessage.value = 'unavailable'
      return
    }
    recoveryMessage.value = result.status === 'accepted' ? null : result.status
    if (result.status === 'accepted') await openAccepted(operation, projectId, workspaceId, binding, result.taskRunId)
  } catch {
    if (operation === scopeOperation.value) recoveryMessage.value = 'unavailable'
  }
}

async function checkStatus() {
  const binding = pending.value
  if (binding === null || busy.value || props.disabled) return
  const operation = scopeOperation.value
  busy.value = true
  try { await reconcile(operation, props.projectId, props.workspaceId, binding) }
  finally { if (operation === scopeOperation.value) busy.value = false }
}

async function startAnotherTask() {
  if (status.value !== 'accepted' || busy.value || props.disabled) return
  const accepted = pending.value
  if (accepted?.acceptedTaskRunId === undefined) return
  let saved
  try { saved = loadPendingRun(props.workspaceId, store()) }
  catch { storageUnavailable.value = true; return }
  if (saved.status === 'pending' && (!sameIntent(saved.binding, accepted)
    || (saved.binding.acceptedTaskRunId !== undefined && saved.binding.acceptedTaskRunId !== accepted.acceptedTaskRunId))) {
    await refreshScope()
    return
  }
  if (saved.status === 'corrupt') { await refreshScope(); return }
  try { clearPendingRun(props.workspaceId, store()) }
  catch { storageUnavailable.value = true; return }
  pending.value = null
  localSubmissionToken.value = null
  await refreshScope()
}

async function submitPrompt() {
  const authority = preflight.value
  if (submitDisabled.value || busy.value || authority === null || authority.conversationId === null || authority.recoveryToken === null || authority.generation === null) return
  const projectId = props.projectId
  const workspaceId = props.workspaceId
  const operation = scopeOperation.value
  let saved
  try { saved = loadPendingRun(workspaceId, store()) }
  catch { storageUnavailable.value = true; return }
  if (saved.status === 'corrupt') {
    pending.value = null
    recoveryMessage.value = 'unavailable'
    status.value = 'uncertain'
    return
  }
  if (saved.status === 'pending') {
    pending.value = saved.binding
    if (saved.binding.acceptedTaskRunId !== undefined) {
      if (saved.binding.navigated === true) {
        status.value = 'accepted'
      } else await openAccepted(operation, projectId, workspaceId, saved.binding, saved.binding.acceptedTaskRunId)
      return
    }
    recoveryMessage.value = 'uncertain'
    status.value = 'uncertain'
    await reconcile(operation, projectId, workspaceId, saved.binding)
    return
  }
  const binding: PendingRunBinding = { recoveryToken: authority.recoveryToken, projectId, workspaceId, conversationId: authority.conversationId }
  try { savePendingRun(binding, store()) }
  catch { storageUnavailable.value = true; return }
  pending.value = binding
  localSubmissionToken.value = authority.recoveryToken
  status.value = 'starting'
  operationFailed.value = false
  busy.value = true
  try {
    const ack = await (props.start ?? startManagedTaskRun)({
      workspaceId, conversationId: authority.conversationId, prompt: prompt.value,
      generation: authority.generation, recoveryToken: authority.recoveryToken,
    })
    if (ack.status === 'accepted') await openAccepted(operation, projectId, workspaceId, binding, ack.taskRunId)
    else {
      if (isCurrent(operation, projectId, workspaceId)) {
        status.value = 'uncertain'
        operationFailed.value = true
      }
      await reconcile(operation, projectId, workspaceId, binding)
    }
  } catch {
    if (operation === scopeOperation.value && props.workspaceId === workspaceId && props.projectId === projectId) {
      operationFailed.value = true
      status.value = 'uncertain'
    }
    await reconcile(operation, projectId, workspaceId, binding)
  } finally { if (operation === scopeOperation.value) busy.value = false }
}

async function openAccepted(operation: number, projectId: string, workspaceId: string, binding: PendingRunBinding, taskRunId: string) {
  const accepted = { ...binding, acceptedTaskRunId: taskRunId, navigated: false }
  if (!isCurrent(operation, projectId, workspaceId)) return
  let canPersist = true
  try {
    const saved = loadPendingRun(workspaceId, store())
    if (saved.status !== 'pending' || !sameIntent(saved.binding, binding)
      || (saved.binding.acceptedTaskRunId !== undefined && saved.binding.acceptedTaskRunId !== taskRunId)) return
    savePendingRun(accepted, store())
  } catch { storageUnavailable.value = true; canPersist = false }
  pending.value = accepted
  if (!isCurrent(operation, projectId, workspaceId)) return
  const ownsSubmission = localSubmissionToken.value === binding.recoveryToken
  if (ownsSubmission) {
    clearDraft(workspaceId)
    prompt.value = ''
  }
  status.value = 'accepted'
  if (!canPersist) storageUnavailable.value = true
  if (!ownsSubmission && prompt.value.length > 0) return
  try {
    await router.push({ name: 'task-run', params: { taskRunId } })
    if (router.currentRoute.value.params.taskRunId === taskRunId) {
      const current = loadPendingRun(workspaceId, store())
      if (current.status === 'pending' && sameIntent(current.binding, binding)
        && current.binding.acceptedTaskRunId === taskRunId) savePendingRun({ ...accepted, navigated: true }, store())
    }
  } catch { /* The accepted identity and explicit timeline link remain visible. */ }
}

function sameIntent(left: PendingRunBinding, right: PendingRunBinding): boolean {
  return left.recoveryToken === right.recoveryToken && left.projectId === right.projectId
    && left.workspaceId === right.workspaceId && left.conversationId === right.conversationId
}

onBeforeUnmount(() => { scopeOperation.value += 1; if (typeof window !== 'undefined') window.removeEventListener('storage', onStorage); setDraft(props.workspaceId, prompt.value) })
</script>

<template>
  <form class="task-composer" aria-labelledby="task-composer-title" @submit.prevent="submitPrompt">
    <h2 id="task-composer-title">{{ translate('taskComposer.title') }}</h2>
    <label for="managed-task-prompt">{{ translate('taskComposer.promptLabel') }}</label>
    <textarea id="managed-task-prompt" v-model="prompt" :disabled="disabled || status === 'starting' || status === 'uncertain' || status === 'accepted'" :placeholder="translate('taskComposer.placeholder')" rows="3" />
    <small>{{ translate('taskComposer.draftPolicy') }}</small>
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
    <RouterLink v-if="status === 'accepted' && pending?.acceptedTaskRunId" :to="{ name: 'task-run', params: { taskRunId: pending.acceptedTaskRunId } }">{{ translate('taskComposer.openAccepted') }}</RouterLink>
    <p v-if="storageUnavailable" role="alert">{{ translate('taskComposer.storageUnavailable') }}</p>
    <p v-if="operationFailed" role="alert">{{ translate('taskComposer.failed') }}</p>
    <p v-if="promptTooLong" role="alert">{{ translate('taskComposer.promptTooLong') }}</p>
    <GcButton v-if="status === 'accepted' && !disabled" type="button" @click="startAnotherTask">{{ translate('taskComposer.newTask') }}</GcButton>
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
