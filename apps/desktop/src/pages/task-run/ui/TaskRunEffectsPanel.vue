<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import type { LocalCommandOutcome, RemoteAvailability, RemoteCancellation, RemoteAccounting, RemotePublication, SuccessorEligibility, TaskRunEffects } from '@/entities/task-run'
import { translate } from '@/shared/i18n'

defineProps<{
  effects: TaskRunEffects | null
  pending: boolean
  unavailable: boolean
  stale: boolean
}>()

function localOutcome(value: LocalCommandOutcome, exitCode: number | null) {
  if (value === 'exited' && exitCode !== null && exitCode !== 0) {
    return translate('taskRun.effects.local.exitFailed')
  }
  switch (value) {
    case 'not_started': return translate('taskRun.effects.local.notStarted')
    case 'running': return translate('taskRun.effects.local.running')
    case 'exited': return translate('taskRun.effects.local.exited')
    default: return translate('taskRun.effects.local.outcomeUnknown')
  }
}

function localStop(value: string) {
  switch (value) {
    case 'requested': return translate('taskRun.effects.local.stopRequested')
    case 'confirmed': return translate('taskRun.effects.local.stopConfirmed')
    case 'unconfirmed': return translate('taskRun.effects.local.stopUnconfirmed')
    default: return translate('taskRun.effects.local.stopNotRequested')
  }
}

function remoteOutcome(value: TaskRunEffects['remote']['outcome']) {
  switch (value) {
    case 'not_applicable': return translate('taskRun.effects.remote.notApplicable')
    case 'not_started': return translate('taskRun.effects.remote.notStarted')
    case 'running': return translate('taskRun.effects.remote.running')
    case 'completed': return translate('taskRun.effects.remote.completed')
    case 'failed': return translate('taskRun.effects.remote.failed')
    case 'incomplete': return translate('taskRun.effects.remote.incomplete')
    case 'cancelled': return translate('taskRun.effects.remote.cancelled')
    default: return translate('taskRun.effects.remote.unknown')
  }
}

function remoteCancellation(value: RemoteCancellation) {
  switch (value) {
    case 'requested': return translate('taskRun.effects.cancelRequestedValue')
    case 'already_terminal': return translate('taskRun.effects.cancelAlreadyTerminal')
    case 'confirmed': return translate('taskRun.effects.cancelConfirmed')
    case 'unconfirmed': return translate('taskRun.effects.cancelUnconfirmed')
    case 'not_requested': return translate('taskRun.effects.cancelNotRequested')
    default: return translate('taskRun.effects.remote.unknown')
  }
}

function publication(value: RemotePublication) {
  switch (value) {
    case 'not_applicable': return translate('taskRun.effects.notApplicable')
    case 'allowed': return translate('taskRun.effects.remote.publicationAllowed')
    case 'withheld': return translate('taskRun.effects.remote.publicationWithheld')
    default: return translate('taskRun.effects.unknown')
  }
}

function accounting(value: RemoteAccounting) {
  switch (value) {
    case 'not_applicable': return translate('taskRun.effects.notApplicable')
    case 'known': return translate('taskRun.effects.remote.accountingKnown')
    default: return translate('taskRun.effects.remote.accountingUnknownValue')
  }
}

function remoteAvailability(value: RemoteAvailability) {
  switch (value) {
    case 'available': return translate('taskRun.effects.available')
    case 'unavailable': return translate('taskRun.effects.unavailableValue')
    case 'not_configured': return translate('taskRun.effects.notConfigured')
    default: return translate('taskRun.effects.unknown')
  }
}

function capabilities(value: TaskRunEffects['remote']['capabilities']) {
  return [
    value.statusCheck && translate('taskRun.effects.statusCheck'),
    value.streamResume && translate('taskRun.effects.streamResume'),
    value.remoteCancel && translate('taskRun.effects.remoteCancel'),
  ].filter(Boolean).join(', ') || translate('taskRun.effects.none')
}

function successorStatus(value: SuccessorEligibility) {
  switch (value) {
    case 'eligible': return translate('taskRun.effects.successorEligible')
    case 'requires_duplicate_effect_acknowledgment': return translate('taskRun.effects.successorNeedsAcknowledgment')
    case 'not_applicable': return translate('taskRun.effects.notApplicable')
    default: return translate('taskRun.effects.blocked')
  }
}
</script>

<template>
  <section class="task-run-effects" aria-live="polite" :aria-label="translate('taskRun.effects.title')">
    <p v-if="pending && effects === null" role="status">{{ translate('taskRun.effects.loading') }}</p>
    <p v-else-if="stale" role="status">{{ translate('taskRun.effects.stale') }}</p>
    <GcAlert v-else-if="unavailable" level="warning" :title="translate('taskRun.effects.unavailable')">
      {{ translate('taskRun.effects.unavailableDetail') }}
    </GcAlert>
    <template v-else-if="effects !== null">
      <h2>{{ translate('taskRun.effects.title') }}</h2>
      <p>{{ translate('taskRun.effects.cancelRequested', { value: effects.cancellationRequested ? translate('taskRun.effects.yes') : translate('taskRun.effects.no') }) }}</p>
      <div v-if="effects.localCommand !== null">
        <h3>{{ translate('taskRun.effects.local.title') }}</h3>
        <p>{{ translate('taskRun.effects.local.outcome', { value: localOutcome(effects.localCommand.outcome, effects.localCommand.exitCode) }) }}</p>
        <p>{{ translate('taskRun.effects.local.stop', { value: localStop(effects.localCommand.stop) }) }}</p>
        <p v-if="effects.localCommand.exitCode !== null" role="status">
          {{ translate('taskRun.effects.local.exitCode', { value: effects.localCommand.exitCode }) }}
        </p>
      </div>
      <div>
        <h3>{{ translate('taskRun.effects.remote.title') }}</h3>
        <p>{{ translate('taskRun.effects.remote.outcome', { value: remoteOutcome(effects.remote.outcome) }) }}</p>
        <p>{{ translate('taskRun.effects.remote.publication', { value: publication(effects.remote.publication) }) }}</p>
        <p>{{ translate('taskRun.effects.remote.accounting', { value: accounting(effects.remote.accounting) }) }}</p>
        <p>{{ translate('taskRun.effects.remote.cancellation', { value: remoteCancellation(effects.remote.cancellation) }) }}</p>
        <p>{{ translate('taskRun.effects.remote.availability', { value: remoteAvailability(effects.remote.availability) }) }}</p>
        <p>{{ translate('taskRun.effects.remote.capabilities', { value: capabilities(effects.remote.capabilities) }) }}</p>
        <p v-if="effects.remote.usageKnown !== null">{{ translate('taskRun.effects.remote.usage', { value: effects.remote.usageKnown ? translate('taskRun.effects.known') : translate('taskRun.effects.no') }) }}</p>
        <p v-if="effects.remote.outcome === 'completed' && effects.remote.accounting === 'unknown'" role="status">
          {{ translate('taskRun.effects.remote.accountingUnknown') }}
        </p>
      </div>
      <p>{{ translate('taskRun.effects.successor', { value: successorStatus(effects.successor) }) }}</p>
      <GcAlert
        v-if="effects.successor === 'requires_duplicate_effect_acknowledgment'"
        level="warning"
        :title="translate('taskRun.effects.successorRiskTitle')"
      >
        {{ translate('taskRun.effects.successorRiskDetail') }}
      </GcAlert>
    </template>
  </section>
</template>
