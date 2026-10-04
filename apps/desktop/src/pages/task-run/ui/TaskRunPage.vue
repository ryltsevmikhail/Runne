<script setup lang="ts">
import { TaskRunWorkspace } from '@runne/product/task-run-workspace'
import { CancelTaskRun } from '@runne/product/cancel-task-run'
import { GcAlert, GcButton } from '@runne/product/shared/ui'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import {
  getTaskRunTimeline,
  cancelTaskRun,
  subscribeTaskRunTimeline,
  getTaskRunEffects,
  type TaskRunSession,
  type TaskRunTimeline,
  type TaskRunEffects,
} from '@/entities/task-run'
import { listPendingApprovals } from '@/entities/approval'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate } from '@/shared/i18n'

import TaskRunRecoveryPanel from './TaskRunRecoveryPanel.vue'
import TaskRunEffectsPanel from './TaskRunEffectsPanel.vue'
import TaskRunSuccessorAction from './TaskRunSuccessorAction.vue'

type LoadTaskRun = (id: string) => Promise<TaskRunTimeline>
type SubscribeTaskRun = (id: string, initial: TaskRunTimeline, onTimeline: (value: TaskRunTimeline) => void) => Promise<TaskRunSession>
type LoadTaskRunEffects = (id: string) => Promise<TaskRunEffects>

const props = withDefaults(defineProps<{
  loadTaskRun?: LoadTaskRun
  subscribeTaskRun?: SubscribeTaskRun
  openBlockedTaskRun?: SubscribeTaskRun
  loadEffects?: LoadTaskRunEffects
}>(), {
  loadTaskRun: getTaskRunTimeline,
  subscribeTaskRun: subscribeTaskRunTimeline,
  openBlockedTaskRun: subscribeTaskRunTimeline,
  loadEffects: getTaskRunEffects,
})

const route = useRoute()
const snapshot = ref<TaskRunTimeline | null>(null)
const effects = ref<TaskRunEffects | null>(null)
const effectsPending = ref(false)
const effectsUnavailable = ref(false)
const effectsMismatch = ref(false)
const unavailable = ref(false)
const resyncing = ref(false)
const cancelling = ref(false)
const approvalAttention = ref(false)
let session: TaskRunSession | null = null
let requestGeneration = 0
let teardown = Promise.resolve()
let resyncOperation = 0
let effectsRequest = 0
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')
const taskRunId = computed(() => typeof route.params.taskRunId === 'string' ? route.params.taskRunId : '')
const lastCommittedAt = computed(() => snapshot.value?.entries.at(-1)?.committedAt ?? null)
// Ветки placeholder'а упорядочены: empty (runtime не сконфигурирован) →
// недоступность операции → loading при живом runtime → ожидание runtime.
const placeholder = computed(() => {
  if (unavailable.value) return translate('taskRun.unavailable')
  if (runtimeStatus.value === 'live') return translate('taskRun.loading')
  return translate('taskRun.waitingForRuntime')
})

function detachSession() {
  const currentSession = session
  session = null
  if (currentSession === null) return teardown
  const priorTeardown = teardown
  const cleanup = currentSession.unsubscribe()
  teardown = priorTeardown.then(() => cleanup, () => cleanup)
  return teardown
}

function markSnapshotReconnecting() {
  if (snapshot.value?.recovery === 'live') snapshot.value = { ...snapshot.value, recovery: 'reconnecting' }
}

function isCurrentLive(generation: number) {
  return generation === requestGeneration && runtimeStatus.value === 'live'
}

async function refreshTaskRun(id: string, generation: number) {
  try {
    await detachSession()
    if (!isCurrentLive(generation)) return
    snapshot.value = null
    unavailable.value = false
    const initial = await props.loadTaskRun(id)
    if (!isCurrentLive(generation)) return
    snapshot.value = initial
    await refreshEffects(initial, generation)
    try {
      approvalAttention.value = (await listPendingApprovals()).some(item => item.taskRunId === id && item.state === 'pending')
    } catch {
      approvalAttention.value = false
    }
    const stableInitial = snapshot.value ?? initial
    const open = stableInitial.recovery === 'live' ? props.subscribeTaskRun : props.openBlockedTaskRun
    if (!isCurrentLive(generation)) return
    let acceptsUpdates = false
    let pendingUpdate: TaskRunTimeline | null = null
    const nextSession = await open(id, stableInitial, (next) => {
      if (!isCurrentLive(generation)) return
      if (acceptsUpdates) { snapshot.value = next; void refreshEffects(next, generation) }
      else pendingUpdate = next
    })
    if (!isCurrentLive(generation)) { pendingUpdate = null; await nextSession.unsubscribe(); return }
    session = nextSession
    acceptsUpdates = true
    if (pendingUpdate !== null && isCurrentLive(generation)) {
      snapshot.value = pendingUpdate
      void refreshEffects(pendingUpdate, generation)
    }
  }
  catch { if (generation === requestGeneration) { markSnapshotReconnecting(); unavailable.value = true } }
}

async function refreshAfterSuccessor(value: { predecessorTaskRunId: string, taskRunId: string }) {
  if (snapshot.value?.taskRunId === value.predecessorTaskRunId && taskRunId.value === value.predecessorTaskRunId) {
    await refreshTaskRun(value.predecessorTaskRunId, requestGeneration)
  }
}

async function refreshEffects(timeline: TaskRunTimeline, generation: number) {
  const request = ++effectsRequest
  effects.value = null
  effectsUnavailable.value = false
  effectsMismatch.value = false
  effectsPending.value = true
  try {
    let next = await props.loadEffects(timeline.taskRunId)
    if (!isCurrentLive(generation) || request !== effectsRequest) return
    if (next.streamVersion !== timeline.streamVersion) {
      const freshTimeline = await props.loadTaskRun(timeline.taskRunId)
      if (!isCurrentLive(generation) || request !== effectsRequest) return
      snapshot.value = freshTimeline
      next = await props.loadEffects(timeline.taskRunId)
      if (!isCurrentLive(generation) || request !== effectsRequest) return
      if (next.streamVersion !== freshTimeline.streamVersion) {
        effectsMismatch.value = true
        return
      }
    } else if (snapshot.value?.streamVersion !== next.streamVersion) {
      effectsMismatch.value = true
      return
    }
    effects.value = next
  } catch {
    if (request === effectsRequest) effectsUnavailable.value = true
  } finally {
    if (request === effectsRequest) effectsPending.value = false
  }
}

watch([taskRunId, runtimeStatus], async ([id, status]) => {
  const generation = ++requestGeneration
  cancelling.value = false
  resyncOperation += 1
  resyncing.value = false
  if (runtimeSession === undefined || status !== 'live') {
    markSnapshotReconnecting()
    await detachSession()
    return
  }
  void refreshTaskRun(id, generation)
}, { immediate: true })

async function resyncTaskRun() {
  if (session === null || snapshot.value?.recovery !== 'resync_required' || runtimeStatus.value !== 'live') return
  const generation = requestGeneration
  const operation = ++resyncOperation
  const currentSession = session
  resyncing.value = true
  try {
    const next = await currentSession.resync()
    if (!isCurrentLive(generation) || session !== currentSession) return
    snapshot.value = next
    void refreshEffects(next, generation)
    if (next.recovery === 'live') {
      await detachSession()
      if (!isCurrentLive(generation) || session !== null) return
      let acceptsUpdates = false
      let pendingUpdate: TaskRunTimeline | null = null
      const nextSession = await props.subscribeTaskRun(next.taskRunId, next, (value) => {
        if (!isCurrentLive(generation)) return
        if (acceptsUpdates) { snapshot.value = value; void refreshEffects(value, generation) }
        else pendingUpdate = value
      })
      if (!isCurrentLive(generation)) { pendingUpdate = null; await nextSession.unsubscribe(); return }
      session = nextSession
      acceptsUpdates = true
      if (pendingUpdate !== null && isCurrentLive(generation)) {
        snapshot.value = pendingUpdate
        void refreshEffects(pendingUpdate, generation)
      }
    }
  }
  catch { if (generation === requestGeneration) { markSnapshotReconnecting(); unavailable.value = true } }
  finally { if (operation === resyncOperation) resyncing.value = false }
}

async function requestCancellation() {
  const current = snapshot.value
  if (current === null || current.recovery !== 'live' || runtimeStatus.value !== 'live' || cancelling.value) return
  const generation = requestGeneration
  cancelling.value = true
  try {
    const acknowledgement = await cancelTaskRun(current.taskRunId, current.streamVersion)
    if (isCurrentLive(generation) && snapshot.value?.taskRunId === current.taskRunId
        && snapshot.value.streamVersion < acknowledgement.streamVersion) {
      await refreshTaskRun(current.taskRunId, generation)
    }
  }
  catch {
    if (generation === requestGeneration && snapshot.value?.taskRunId === current.taskRunId) unavailable.value = true
  }
  finally { if (generation === requestGeneration) cancelling.value = false }
}

onBeforeUnmount(() => { requestGeneration += 1; resyncOperation += 1; resyncing.value = false; void detachSession() })
</script>

<template>
  <section v-if="snapshot === null && runtimeStatus === 'empty'" role="status">
    {{ translate('taskRun.runtimeNotConfigured') }}
  </section>
  <section v-else-if="snapshot === null" aria-live="polite">
    {{ placeholder }}
  </section>
  <template v-else>
    <TaskRunWorkspace
      :state="snapshot.state"
      :entries="snapshot.entries"
      :active-attempt-id="snapshot.activeAttemptId"
      :terminal="snapshot.terminal"
      :recovery="snapshot.recovery"
      :approval-attention="approvalAttention"
    />
    <TaskRunEffectsPanel
      :effects="effects?.streamVersion === snapshot.streamVersion ? effects : null"
      :pending="effectsPending"
      :unavailable="effectsUnavailable"
      :stale="effectsMismatch || (effects !== null && effects.streamVersion !== snapshot.streamVersion)"
    />
    <TaskRunSuccessorAction
      v-if="effects?.streamVersion === snapshot.streamVersion && ['running', 'cancelling', 'unrecoverable', 'cancelled'].includes(snapshot.state)"
      :key="snapshot.taskRunId"
      :task-run-id="snapshot.taskRunId"
      :expected-version="snapshot.streamVersion"
      :eligibility="effects?.streamVersion === snapshot.streamVersion ? effects.successor : 'blocked'"
      :runtime-live="runtimeStatus === 'live'"
      @created="refreshAfterSuccessor"
    />
    <p v-if="snapshot.entries.length === 0" role="status">
      {{ translate('taskRun.noRecordedEvents') }}
    </p>
    <TaskRunRecoveryPanel
      v-if="snapshot.recovery !== 'live'"
      :recovery="snapshot.recovery"
      :projection-revision="snapshot.projectionRevision"
      :stream-version="snapshot.streamVersion"
      :last-committed-at="lastCommittedAt"
    />
    <GcAlert v-if="unavailable" level="error" :title="translate('taskRun.lastOperationFailed')">
      {{ translate('taskRun.operationFailedNotice') }}
    </GcAlert>
  </template>
  <CancelTaskRun
    v-if="snapshot?.recovery === 'live' && snapshot.terminal === null && ['created', 'queued', 'admitted', 'running', 'waiting', 'retrying', 'checkpointing'].includes(snapshot.state)"
    :disabled="runtimeStatus !== 'live'"
    :pending="cancelling"
    @request="requestCancellation"
  />
  <GcButton
    v-if="snapshot?.recovery === 'resync_required'"
    variant="secondary"
    :disabled="resyncing || runtimeStatus !== 'live'"
    @click="resyncTaskRun"
  >
    {{ translate('taskRun.revalidate') }}
  </GcButton>
</template>
