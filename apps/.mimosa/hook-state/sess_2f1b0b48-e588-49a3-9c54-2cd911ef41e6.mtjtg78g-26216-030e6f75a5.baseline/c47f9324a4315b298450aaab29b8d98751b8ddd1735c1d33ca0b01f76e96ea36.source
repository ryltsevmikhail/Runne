import type {
  ExpiryAggregate,
  HostLifecycleEntry,
  HostLifecycleEvent,
  OperationalTelemetrySnapshot,
  RuntimeBudget,
  RuntimeOperationalTelemetry,
  TelemetrySectionMeta,
} from './operational-telemetry.types'

export function isOperationalTelemetrySemanticallyValid(
  snapshot: OperationalTelemetrySnapshot,
): boolean {
  return isMetaValid(snapshot.runtime.meta)
    && isMetaValid(snapshot.hostLifecycle.meta)
    && snapshot.runtime.meta.observedAtUnixSeconds === snapshot.observedAtUnixSeconds
    && snapshot.hostLifecycle.meta.observedAtUnixSeconds === snapshot.observedAtUnixSeconds
    && isRuntimeValid(snapshot.runtime)
    && isHostLifecycleValid(snapshot)
}

function isRuntimeValid(runtime: OperationalTelemetrySnapshot['runtime']): boolean {
  if (isObservedComplete(runtime.meta)) return runtime.snapshot !== null && isSnapshotValid(runtime.snapshot)
  return isUnavailable(runtime.meta) && runtime.snapshot === null
}

function isSnapshotValid(snapshot: RuntimeOperationalTelemetry): boolean {
  return snapshot.launchGeneration > 0
    && isDurableValid(snapshot.durable)
    && isRecoveryValid(snapshot.recoveryTransient)
}

function isDurableValid(durable: RuntimeOperationalTelemetry['durable']): boolean {
  const present = [
    durable.accounting,
    durable.providerEffectAuthorities,
    durable.providerApprovalLease,
    durable.committedProviderEffects,
    durable.uncertainAttempts,
  ].filter((value) => value !== null).length
  const expected = present === 0 ? 'unavailable' : present === 5 ? 'complete' : 'partial'
  return isMetaValid(durable.meta)
    && durable.meta.completeness === expected
    && (durable.accounting === null || isAccountingValid(durable.accounting))
    && [
      durable.providerEffectAuthorities,
      durable.providerApprovalLease,
      durable.committedProviderEffects,
    ].every((aggregate) => aggregate === null || isAggregateValid(aggregate, durable.meta))
}

function isAccountingValid(accounting: NonNullable<RuntimeOperationalTelemetry['durable']['accounting']>): boolean {
  return isBudgetValid(accounting.tokens) && isBudgetValid(accounting.costMicroUsd)
}

function isBudgetValid(budget: RuntimeBudget): boolean {
  const total = budget.reserved + budget.settled + budget.remaining
  return Number.isSafeInteger(total) && total === budget.limit
}

function isAggregateValid(aggregate: ExpiryAggregate, meta: TelemetrySectionMeta): boolean {
  return aggregate.expiredActiveCount <= aggregate.activeCount
    && (aggregate.nearestUnexpiredExpiryUnixSeconds === null
      || aggregate.nearestUnexpiredExpiryUnixSeconds > meta.observedAtUnixSeconds)
}

function isRecoveryValid(recovery: RuntimeOperationalTelemetry['recoveryTransient']): boolean {
  if (recovery.counterSaturated) return false
  switch (recovery.status) {
    case 'lower_bound_since_launch':
      return recovery.observedOutboxRecoveriesInGeneration !== null
        && recovery.droppedEventCount === 0
        && isObservedComplete(recovery.meta)
    case 'truncated_lower_bound_since_launch':
      return recovery.observedOutboxRecoveriesInGeneration !== null
        && recovery.droppedEventCount > 0
        && isObservedPartial(recovery.meta)
    case 'unavailable':
      return recovery.observedOutboxRecoveriesInGeneration === null
        && isUnavailable(recovery.meta)
  }
}

function isHostLifecycleValid(snapshot: OperationalTelemetrySnapshot): boolean {
  const host = snapshot.hostLifecycle
  if (host.producerDropCounterSaturated || host.evictionCounterSaturated) return false
  if (isUnavailable(host.meta)) {
    return host.current === null && host.events === null && host.eventStatus === 'unavailable'
  }
  if (!isObserved(host.meta) || host.current === null || !isHostEntryValid(host.current, host.runtimeMode)) {
    return false
  }
  if (!isEventsValid(host.events, host.lastAllocatedSequence, host.runtimeMode)) return false
  const truncated = host.producerDroppedEventCount > 0 || host.evictedEventCount > 0
  switch (host.eventStatus) {
    case 'complete_since_app_core_start':
      return host.events !== null && !truncated && host.meta.completeness === 'complete'
    case 'truncated_since_app_core_start':
      return host.events !== null && truncated && host.meta.completeness === 'partial'
    case 'unavailable':
      return host.events === null && host.meta.completeness === 'partial'
  }
}

function isEventsValid(
  events: readonly HostLifecycleEvent[] | null,
  lastAllocatedSequence: number | null,
  mode: OperationalTelemetrySnapshot['hostLifecycle']['runtimeMode'],
): boolean {
  if (events === null) return true
  if (events.length === 0) return lastAllocatedSequence === null
  const finalSequence = events.at(-1)?.sequence
  return finalSequence !== undefined
    && lastAllocatedSequence !== null
    && lastAllocatedSequence >= finalSequence
    && events.every((event, index) => {
      const previous = index === 0 ? undefined : events[index - 1]
      return isHostEntryValid(event, mode)
        && event.sequence > 0
        && (previous === undefined || event.sequence > previous.sequence)
    })
}

function isHostEntryValid(
  entry: HostLifecycleEntry,
  mode: OperationalTelemetrySnapshot['hostLifecycle']['runtimeMode'],
): boolean {
  const failureValid = entry.lifecycle === 'configuration_required'
    ? entry.failure === 'configuration_required'
    : ['starting', 'ready', 'restarting', 'external'].includes(entry.lifecycle)
      ? entry.failure === null
      : true
  if (!failureValid) return false
  return mode === 'external_local'
    ? entry.lifecycle === 'external'
      && entry.restartOrdinal === null
      && entry.runtimeLaunchGeneration === null
    : entry.lifecycle !== 'external'
      && entry.restartOrdinal !== null
      && entry.runtimeLaunchGeneration !== null
}

function isMetaValid(meta: TelemetrySectionMeta): boolean {
  return isObserved(meta) || isUnavailable(meta)
}

function isObserved(meta: TelemetrySectionMeta): boolean {
  return meta.freshness === 'observed_in_current_cycle'
    && (meta.completeness === 'complete' || meta.completeness === 'partial')
}

function isObservedComplete(meta: TelemetrySectionMeta): boolean {
  return meta.freshness === 'observed_in_current_cycle' && meta.completeness === 'complete'
}

function isObservedPartial(meta: TelemetrySectionMeta): boolean {
  return meta.freshness === 'observed_in_current_cycle' && meta.completeness === 'partial'
}

function isUnavailable(meta: TelemetrySectionMeta): boolean {
  return meta.freshness === 'unavailable' && meta.completeness === 'unavailable'
}
