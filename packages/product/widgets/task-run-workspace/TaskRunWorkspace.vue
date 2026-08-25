<script setup lang="ts">
import { GcAlert } from '../../shared/ui'
import { TaskRunTimeline, type TaskRunTimelineEntry } from '../../entities/task-run'

export type TaskRunState = 'created' | 'queued' | 'admitted' | 'running' | 'waiting' | 'retrying' | 'checkpointing' | 'cancelling' | 'reconciling' | 'succeeded' | 'failed' | 'cancelled' | 'budget_exhausted' | 'policy_denied' | 'unrecoverable'
export type TaskRunRecovery = 'live' | 'reconnecting' | 'incompatible' | 'revoked' | 'resync_required' | 'fatal'
export type TaskRunTerminal = 'success' | 'failure' | 'cancelled' | 'budget_exhausted' | 'policy_denied' | 'unrecoverable'

const states: readonly TaskRunState[] = ['created', 'queued', 'admitted', 'running', 'waiting', 'retrying', 'checkpointing', 'cancelling', 'reconciling', 'succeeded', 'failed', 'cancelled', 'budget_exhausted', 'policy_denied', 'unrecoverable']
const recoveries: readonly TaskRunRecovery[] = ['live', 'reconnecting', 'incompatible', 'revoked', 'resync_required', 'fatal']
const terminals: readonly TaskRunTerminal[] = ['success', 'failure', 'cancelled', 'budget_exhausted', 'policy_denied', 'unrecoverable']
const props = defineProps<{
  readonly state: TaskRunState
  readonly entries: readonly TaskRunTimelineEntry[]
  readonly activeAttemptId: string | null
  readonly terminal: TaskRunTerminal | null
  readonly recovery: TaskRunRecovery
  readonly approvalAttention?: boolean
}>()
const valid = () => states.includes(props.state) && recoveries.includes(props.recovery) && (props.terminal === null || terminals.includes(props.terminal))
</script>

<template>
  <section v-if="!valid()" role="alert">Task run is unavailable.</section>
  <section v-else aria-labelledby="task-run-title">
    <header>
      <p>Task run</p>
      <h1 id="task-run-title">{{ state.replaceAll('_', ' ') }}</h1>
      <p v-if="activeAttemptId !== null">Active attempt {{ activeAttemptId }}</p>
    </header>
    <GcAlert
      v-if="recovery !== 'live'"
      level="warning"
      title="Task run is read-only"
    >
      Replay recovery is {{ recovery }}. Confirmed events remain available.
    </GcAlert>
    <GcAlert
      v-if="terminal !== null"
      :level="terminal === 'success' ? 'success' : 'warning'"
      :title="`Terminal result: ${terminal.replaceAll('_', ' ')}`"
    >
      This result is authoritative runtime state.
    </GcAlert>
    <TaskRunTimeline :entries="entries" />
    <p v-if="approvalAttention" aria-live="polite">
      <a href="/approvals">An approval is waiting for review.</a>
    </p>
  </section>
</template>
