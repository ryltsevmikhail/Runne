<script setup lang="ts">
export interface TaskRunTimelineEntry {
  readonly eventId: string
  readonly sequence: number
  readonly committedAt: number
  readonly kind: TaskRunTimelineKind
  readonly attemptId: string | null
}

export type TaskRunTimelineKind = 'created' | 'queued' | 'admitted' | 'attempt_started' | 'wait_started' | 'resumed' | 'retrying' | 'checkpoint_started' | 'checkpoint_committed' | 'cancellation_requested' | 'cancellation_completed' | 'cancelled' | 'completed' | 'failed' | 'budget_exhausted' | 'policy_denied' | 'reconciliation_started' | 'reconciliation_completed' | 'unrecoverable' | 'cycle_started' | 'context_committed' | 'plan_committed' | 'step_outcome_recorded' | 'cycle_completed' | 'next_cycle_created' | 'retry_scheduled' | 'retry_attempt_activated' | 'recovery_resume_started' | 'loop_checkpoint_started' | 'loop_checkpoint_recorded' | 'loop_checkpoint_committed' | 'loop_wake_accepted'

const kinds: readonly TaskRunTimelineKind[] = ['created', 'queued', 'admitted', 'attempt_started', 'wait_started', 'resumed', 'retrying', 'checkpoint_started', 'checkpoint_committed', 'cancellation_requested', 'cancellation_completed', 'cancelled', 'completed', 'failed', 'budget_exhausted', 'policy_denied', 'reconciliation_started', 'reconciliation_completed', 'unrecoverable', 'cycle_started', 'context_committed', 'plan_committed', 'step_outcome_recorded', 'cycle_completed', 'next_cycle_created', 'retry_scheduled', 'retry_attempt_activated', 'recovery_resume_started', 'loop_checkpoint_started', 'loop_checkpoint_recorded', 'loop_checkpoint_committed', 'loop_wake_accepted']

const props = defineProps<{
  readonly entries: readonly TaskRunTimelineEntry[]
}>()
const valid = () => props.entries.every(entry => kinds.includes(entry.kind))
</script>

<template>
  <p v-if="!valid()" role="alert">Task run timeline is unavailable.</p>
  <ol v-else aria-label="Task run timeline">
    <li
      v-for="entry in entries"
      :key="entry.eventId"
      :data-event-id="entry.eventId"
    >
      <strong>{{ entry.kind.replaceAll('_', ' ') }}</strong>
      <span v-if="entry.attemptId !== null">Attempt {{ entry.attemptId }}</span>
    </li>
    <li v-if="entries.length === 0">No canonical events have been recorded.</li>
  </ol>
</template>
