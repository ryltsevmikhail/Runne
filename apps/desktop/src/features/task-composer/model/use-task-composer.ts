import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { isNavigationFailure, useRouter } from 'vue-router'
import {
  prepareManagedTaskRun, recoverManagedTaskRun, startManagedTaskRun,
} from '@/entities/task-run/api/managed-task-run'
import type { ManagedTaskRunPreflight } from '@/entities/task-run/api/managed-task-run'
import type { DraftApi, DraftScope, SubmittedDraft } from './draft-session'
import { DraftSession } from './draft-session'
import { clearPendingRun, loadPendingRun, samePendingRunIntent, savePendingRun } from './pending-run'
import type { PendingRunBinding } from './pending-run'
import { useTaskComposerScope } from './task-composer-scope'
import type { ComposerStatus } from './task-composer-scope'

const maxPromptBytes = 64 * 1024
export interface TaskComposerOptions {
  readonly projectId: string
  readonly workspaceId: string
  readonly disabled: boolean
  readonly prepare?: typeof prepareManagedTaskRun | undefined
  readonly start?: typeof startManagedTaskRun | undefined
  readonly recover?: typeof recoverManagedTaskRun | undefined
  readonly storage?: Storage | undefined
  readonly draftApi?: DraftApi | undefined
}
export function useTaskComposer(props: TaskComposerOptions) {
  const router = useRouter()
  let revalidateDraftScope: (scope: DraftScope) => void = () => undefined
  const draft = new DraftSession(props.draftApi, 250, scope => revalidateDraftScope(scope))
  const preflight = ref<ManagedTaskRunPreflight | null>(null)
  const status = ref<ComposerStatus>('waiting')
  const recoveryMessage = ref<'not_committed' | 'uncertain' | 'unavailable' | 'newer_draft' | null>(null)
  const recoveryStorageUnavailable = ref(false)
  const operationFailed = ref(false)
  const scopeOperation = ref(0)
  const pending = ref<PendingRunBinding | null>(null)
  const localSubmissionToken = ref<string | null>(null)
  const draftCleanupReady = ref(false)
  const draftVisible = ref(false)
  const busy = ref(false)
  const promptTooLong = computed(() => draftVisible.value && new TextEncoder().encode(draft.view.prompt).length > maxPromptBytes)
  const draftReady = computed(() => draft.view.policy === 'memory_only'
    ? draft.view.status === 'memory'
    : draft.view.policy === 'protected_restart'
      && ['saved', 'unsaved', 'saving'].includes(draft.view.status))
  const submitDisabled = computed(() => !draftVisible.value || props.disabled || busy.value || status.value !== 'ready'
    || !draftReady.value || draft.view.prompt.trim().length === 0 || promptTooLong.value)
  const textareaDisabled = computed(() => !draftVisible.value || props.disabled || busy.value || status.value === 'starting'
    || status.value === 'preparing' || status.value === 'uncertain' || status.value === 'accepted'
    || ['unknown', 'loading', 'error', 'conflict', 'unavailable'].includes(draft.view.status)
    || draft.view.policy === 'unavailable')

  function storage(): Storage { return props.storage ?? localStorage }
  function current(operation: number, projectId: string, workspaceId: string): boolean {
    return operation === scopeOperation.value && props.projectId === projectId
      && props.workspaceId === workspaceId && !props.disabled
  }
  const { activateScope, refreshScope } = useTaskComposerScope({
    props, draft, scopeOperation, preflight, status, recoveryMessage, recoveryStorageUnavailable,
    operationFailed, pending, localSubmissionToken, draftCleanupReady, draftVisible, busy,
    current, storage, reconcile, completeAccepted,
  })
  revalidateDraftScope = scope => {
    if (props.disabled || props.projectId !== scope.projectId || props.workspaceId !== scope.workspaceId || pending.value !== null) return
    void refreshScope()
  }
  watch([() => props.projectId, () => props.workspaceId], () => { void activateScope() }, { immediate: true })
  watch(() => props.disabled, () => { void refreshScope() })
  async function reconcile(operation: number, projectId: string, workspaceId: string, binding: PendingRunBinding): Promise<void> {
    if (!current(operation, projectId, workspaceId)) return
    try {
      const result = await (props.recover ?? recoverManagedTaskRun)(binding.recoveryToken)
      if (operation !== scopeOperation.value || props.workspaceId !== workspaceId || props.projectId !== projectId) return
      if (result.status === 'accepted') {
        if (result.workspaceId !== binding.workspaceId || result.conversationId !== binding.conversationId) {
          recoveryMessage.value = 'unavailable'
          return
        }
        await completeAccepted(operation, projectId, workspaceId, binding, result.taskRunId)
        return
      }
      recoveryMessage.value = result.status
    } catch {
      if (operation === scopeOperation.value) recoveryMessage.value = 'unavailable'
    }
  }
  async function checkStatus(): Promise<void> {
    const binding = pending.value
    if (binding === null || busy.value || props.disabled) return
    const operation = scopeOperation.value
    busy.value = true
    try { await reconcile(operation, props.projectId, props.workspaceId, binding) }
    finally { if (operation === scopeOperation.value) busy.value = false }
  }
  async function submitPrompt(): Promise<void> {
    const authority = preflight.value
    if (submitDisabled.value || authority === null || authority.conversationId === null
        || authority.recoveryToken === null || authority.generation === null) return
    const projectId = props.projectId
    const workspaceId = props.workspaceId
    const operation = scopeOperation.value
    busy.value = true
    try {
      const saved = loadPendingRun(workspaceId, storage())
      if (saved.status === 'corrupt') { status.value = 'uncertain'; recoveryMessage.value = 'unavailable'; return }
      if (saved.status === 'pending') {
        pending.value = saved.binding
        status.value = saved.binding.acceptedTaskRunId ? 'accepted' : 'uncertain'
        if (saved.binding.acceptedTaskRunId) await completeAccepted(operation, projectId, workspaceId, saved.binding, saved.binding.acceptedTaskRunId)
        else await reconcile(operation, projectId, workspaceId, saved.binding)
        return
      }
      let draftRef: SubmittedDraft | null
      try { draftRef = await draft.flush() }
      catch {
        if (current(operation, projectId, workspaceId)
            && (draft.view.status === 'conflict' || draft.view.policy === 'unknown')) await refreshScope()
        return
      }
      if (!current(operation, projectId, workspaceId)) return
      let latest
      try { latest = loadPendingRun(workspaceId, storage()) }
      catch { recoveryStorageUnavailable.value = true; return }
      if (latest.status === 'corrupt') {
        status.value = 'uncertain'
        recoveryMessage.value = 'unavailable'
        return
      }
      if (latest.status === 'pending') {
        pending.value = latest.binding
        if (latest.binding.acceptedTaskRunId !== undefined) {
          await completeAccepted(operation, projectId, workspaceId, latest.binding, latest.binding.acceptedTaskRunId)
        } else {
          status.value = 'uncertain'
          await reconcile(operation, projectId, workspaceId, latest.binding)
        }
        return
      }
      const binding: PendingRunBinding = {
        recoveryToken: authority.recoveryToken, projectId, workspaceId, conversationId: authority.conversationId,
        ...(draftRef === null ? {} : { draftScopeToken: draftRef.scopeToken, draftRevision: draftRef.revision }),
      }
      try { savePendingRun(binding, storage()) }
      catch { recoveryStorageUnavailable.value = true; return }
      pending.value = binding
      localSubmissionToken.value = authority.recoveryToken
      status.value = 'starting'
      operationFailed.value = false
      const ack = await (props.start ?? startManagedTaskRun)({
        workspaceId, conversationId: authority.conversationId, prompt: draft.view.prompt,
        generation: authority.generation, recoveryToken: authority.recoveryToken,
      })
      if (ack.status === 'accepted') await completeAccepted(operation, projectId, workspaceId, binding, ack.taskRunId)
      else {
        if (!current(operation, projectId, workspaceId)) return
        status.value = 'uncertain'
        operationFailed.value = true
        await reconcile(operation, projectId, workspaceId, binding)
      }
    } catch {
      if (operation === scopeOperation.value) { operationFailed.value = true; status.value = 'uncertain' }
      if (pending.value !== null) await reconcile(operation, projectId, workspaceId, pending.value)
    } finally { if (operation === scopeOperation.value) busy.value = false }
  }
  async function completeAccepted(operation: number, projectId: string, workspaceId: string, binding: PendingRunBinding, taskRunId: string): Promise<void> {
    if (!current(operation, projectId, workspaceId)) return
    const accepted: PendingRunBinding = { ...binding, acceptedTaskRunId: taskRunId, navigated: binding.navigated === true }
    try {
      const saved = loadPendingRun(workspaceId, storage())
      if (saved.status === 'pending' && (!samePendingRunIntent(saved.binding, binding)
          || (saved.binding.acceptedTaskRunId !== undefined && saved.binding.acceptedTaskRunId !== taskRunId))) {
        pending.value = saved.binding
        status.value = saved.binding.acceptedTaskRunId === undefined ? 'uncertain' : 'accepted'
        recoveryMessage.value = 'unavailable'
        return
      }
      if (saved.status !== 'pending') {
        recoveryStorageUnavailable.value = true
        pending.value = accepted
        status.value = 'accepted'
        draftCleanupReady.value = false
        recoveryMessage.value = 'unavailable'
        return
      }
      savePendingRun(accepted, storage())
    } catch { recoveryStorageUnavailable.value = true }
    pending.value = accepted
    const cleanup = binding.draftScopeToken === undefined || binding.draftRevision === undefined ? 'cleared'
      : await draft.clearSubmitted({ projectId, workspaceId }, { scopeToken: binding.draftScopeToken, revision: binding.draftRevision })
    if (operation !== scopeOperation.value) return
    if (binding.draftScopeToken === undefined && localSubmissionToken.value === binding.recoveryToken) draft.clearMemory()
    draftCleanupReady.value = cleanup !== 'blocked'
    recoveryMessage.value = cleanup === 'newer' ? 'newer_draft' : cleanup === 'blocked' ? 'unavailable' : null
    status.value = 'accepted'
    if (cleanup === 'blocked' || cleanup === 'newer' || binding.navigated === true) return
    const ownsSubmission = localSubmissionToken.value === binding.recoveryToken
    if (!ownsSubmission && draft.view.prompt.length > 0) return
    await navigateAccepted(operation, workspaceId, accepted, taskRunId)
  }
  async function navigateAccepted(operation: number, workspaceId: string, binding: PendingRunBinding, taskRunId: string): Promise<void> {
    try {
      const result = await router.push({ name: 'task-run', params: { taskRunId } })
      const route = router.currentRoute.value
      if (isNavigationFailure(result) || route.name !== 'task-run' || String(route.params.taskRunId) !== taskRunId) return
      const currentBinding = loadPendingRun(workspaceId, storage())
      if (currentBinding.status === 'pending' && samePendingRunIntent(currentBinding.binding, binding)
          && currentBinding.binding.acceptedTaskRunId === taskRunId) {
        const navigated = { ...currentBinding.binding, navigated: true }
        savePendingRun(navigated, storage())
        if (operation === scopeOperation.value && props.projectId === binding.projectId
            && props.workspaceId === workspaceId && !props.disabled) pending.value = navigated
      }
    } catch { /* The accepted task remains linked from the composer. */ }
  }
  async function retryDraftCleanup(): Promise<void> {
    const accepted = pending.value
    if (accepted?.acceptedTaskRunId === undefined || busy.value || props.disabled) return
    busy.value = true
    const operation = scopeOperation.value
    try { await completeAccepted(operation, props.projectId, props.workspaceId, accepted, accepted.acceptedTaskRunId) }
    finally { if (operation === scopeOperation.value) busy.value = false }
  }
  async function reconcileDraft(choice: 'keep_local' | 'use_saved'): Promise<void> {
    const operation = scopeOperation.value
    const projectId = props.projectId
    const workspaceId = props.workspaceId
    await draft.reconcileConflict(choice)
    if (operation === scopeOperation.value && props.projectId === projectId && props.workspaceId === workspaceId
        && !props.disabled && draft.view.policy === 'unknown') await refreshScope()
  }
  async function startAnotherTask(): Promise<void> {
    const accepted = pending.value
    if (!draftCleanupReady.value || status.value !== 'accepted' || accepted?.acceptedTaskRunId === undefined
        || busy.value || props.disabled) return
    let saved
    try { saved = loadPendingRun(props.workspaceId, storage()) }
    catch { recoveryStorageUnavailable.value = true; return }
    if (saved.status === 'corrupt') { await refreshScope(); return }
    if (saved.status === 'pending' && (!samePendingRunIntent(saved.binding, accepted)
        || saved.binding.acceptedTaskRunId !== accepted.acceptedTaskRunId)) { await refreshScope(); return }
    try { clearPendingRun(props.workspaceId, storage()) }
    catch { recoveryStorageUnavailable.value = true; return }
    pending.value = null
    localSubmissionToken.value = null
    status.value = 'waiting'
    await refreshScope()
  }
  function onStorage(event: StorageEvent): void {
    if (event.key === `runne:managed-task-run:${props.workspaceId}`) void refreshScope()
  }
  if (typeof window !== 'undefined') window.addEventListener('storage', onStorage)
  onBeforeUnmount(() => {
    scopeOperation.value += 1
    if (typeof window !== 'undefined') window.removeEventListener('storage', onStorage)
    void draft.release()
  })
  return {
    draft, status, recoveryMessage, recoveryStorageUnavailable, operationFailed, pending, busy,
    draftCleanupReady, draftVisible, promptTooLong, submitDisabled, textareaDisabled,
    setPrompt: (value: string) => draft.edit(value), reconcileDraft,
    submitPrompt, checkStatus, startAnotherTask, retryDraftCleanup,
  }
}
