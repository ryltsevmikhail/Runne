import { isRuntimeFailureCode, isRuntimeLifecycleStatus, isRuntimeMode } from './bootstrap'
import type {
  ExpiryAggregate,
  HostLifecycleEntry,
  HostLifecycleEvent,
  OperationalTelemetrySnapshot,
  RuntimeBudget,
  RuntimeOperationalTelemetry,
  TelemetrySectionMeta,
} from './operational-telemetry.types'
import { isOperationalTelemetrySemanticallyValid } from './operational-telemetry.semantics'

type RecordValue = Record<string, unknown>

const freshness = ['observed_in_current_cycle', 'unavailable'] as const
const completeness = ['complete', 'partial', 'unavailable'] as const
const recoveryStatuses = [
  'lower_bound_since_launch',
  'truncated_lower_bound_since_launch',
  'unavailable',
] as const
const eventStatuses = [
  'complete_since_app_core_start',
  'truncated_since_app_core_start',
  'unavailable',
] as const

export function hasExactKeys(record: RecordValue, keys: readonly string[]): boolean {
  return Object.keys(record).length === keys.length && keys.every((key) => key in record)
}

export function isSafeU64(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export function isNullableSafeU64(value: unknown): value is number | null {
  return value === null || isSafeU64(value)
}

export function parseOperationalTelemetry(value: unknown): OperationalTelemetrySnapshot | null {
  const record = exactRecord(value, ['schemaVersion', 'observedAtUnixSeconds', 'runtime', 'hostLifecycle'])
  if (!record || record.schemaVersion !== 1 || !isSafeU64(record.observedAtUnixSeconds)) return null
  const runtime = parseRuntime(record.runtime)
  const hostLifecycle = parseHostLifecycle(record.hostLifecycle)
  const snapshot = runtime && hostLifecycle ? freeze({
    schemaVersion: 1,
    observedAtUnixSeconds: record.observedAtUnixSeconds,
    runtime,
    hostLifecycle,
  }) : null
  return snapshot !== null && isOperationalTelemetrySemanticallyValid(snapshot) ? snapshot : null
}

function parseRuntime(value: unknown): OperationalTelemetrySnapshot['runtime'] | null {
  const record = exactRecord(value, ['meta', 'snapshot'])
  if (!record) return null
  const meta = parseMeta(record.meta)
  const snapshot = record.snapshot === null ? null : parseRuntimeSnapshot(record.snapshot)
  return meta && (record.snapshot === null || snapshot) ? freeze({ meta, snapshot }) : null
}

function parseHostLifecycle(value: unknown): OperationalTelemetrySnapshot['hostLifecycle'] | null {
  const record = exactRecord(value, [
    'meta', 'runtimeMode', 'current', 'events', 'eventStatus', 'lastAllocatedSequence',
    'producerDroppedEventCount', 'producerDropCounterSaturated', 'evictedEventCount',
    'evictionCounterSaturated',
  ])
  if (!record || !isRuntimeMode(record.runtimeMode) || !isOneOf(record.eventStatus, eventStatuses)
    || !isNullableSafeU64(record.lastAllocatedSequence)
    || !isSafeU64(record.producerDroppedEventCount) || typeof record.producerDropCounterSaturated !== 'boolean'
    || !isSafeU64(record.evictedEventCount) || typeof record.evictionCounterSaturated !== 'boolean') return null
  const meta = parseMeta(record.meta)
  const current = record.current === null ? null : parseEntry(record.current, false)
  const events = parseEvents(record.events)
  return meta && (record.current === null || current) && events !== undefined ? freeze({
    meta,
    runtimeMode: record.runtimeMode,
    current,
    events,
    eventStatus: record.eventStatus,
    lastAllocatedSequence: record.lastAllocatedSequence,
    producerDroppedEventCount: record.producerDroppedEventCount,
    producerDropCounterSaturated: record.producerDropCounterSaturated,
    evictedEventCount: record.evictedEventCount,
    evictionCounterSaturated: record.evictionCounterSaturated,
  }) : null
}

function parseEvents(value: unknown): readonly HostLifecycleEvent[] | null | undefined {
  if (value === null) return null
  if (!Array.isArray(value) || value.length > 64) return undefined
  const events = value.map((event) => parseEntry(event, true))
  return events.every((event): event is HostLifecycleEvent => event !== null) ? freeze(events) : undefined
}

function parseEntry(value: unknown, event: boolean): HostLifecycleEntry | HostLifecycleEvent | null {
  const keys = ['lifecycle', 'failure', 'restartOrdinal', 'runtimeLaunchGeneration', 'observedAtUnixSeconds']
  if (event) keys.unshift('sequence')
  const record = exactRecord(value, keys)
  if (!record || !isRuntimeLifecycleStatus(record.lifecycle)
    || !(record.failure === null || isRuntimeFailureCode(record.failure))
    || !isNullableSafeU64(record.restartOrdinal) || !isNullableSafeU64(record.runtimeLaunchGeneration)
    || !isSafeU64(record.observedAtUnixSeconds) || (event && !isSafeU64(record.sequence))) return null
  const entry = {
    lifecycle: record.lifecycle,
    failure: record.failure,
    restartOrdinal: record.restartOrdinal,
    runtimeLaunchGeneration: record.runtimeLaunchGeneration,
    observedAtUnixSeconds: record.observedAtUnixSeconds,
  }
  return event ? freeze({ sequence: record.sequence as number, ...entry }) : freeze(entry)
}

function parseRuntimeSnapshot(value: unknown): RuntimeOperationalTelemetry | null {
  const record = exactRecord(value, [
    'schemaVersion', 'observedAtUnixSeconds', 'launchGeneration', 'durable', 'recoveryTransient',
  ])
  if (!record || record.schemaVersion !== 1 || !isSafeU64(record.observedAtUnixSeconds)
    || !isSafeU64(record.launchGeneration)) return null
  const durable = parseDurable(record.durable)
  const recoveryTransient = parseRecovery(record.recoveryTransient)
  return durable && recoveryTransient ? freeze({
    schemaVersion: 1,
    observedAtUnixSeconds: record.observedAtUnixSeconds,
    launchGeneration: record.launchGeneration,
    durable,
    recoveryTransient,
  }) : null
}

function parseDurable(value: unknown): RuntimeOperationalTelemetry['durable'] | null {
  const record = exactRecord(value, [
    'meta', 'accounting', 'providerEffectAuthorities', 'providerApprovalLease',
    'committedProviderEffects', 'uncertainAttempts',
  ])
  if (!record || !isNullableSafeU64(record.uncertainAttempts)) return null
  const meta = parseMeta(record.meta)
  const accounting = parseNullable(record.accounting, parseAccounting)
  const providerEffectAuthorities = parseNullable(record.providerEffectAuthorities, parseAggregate)
  const providerApprovalLease = parseNullable(record.providerApprovalLease, parseAggregate)
  const committedProviderEffects = parseNullable(record.committedProviderEffects, parseAggregate)
  return meta && accounting !== undefined && providerEffectAuthorities !== undefined
    && providerApprovalLease !== undefined && committedProviderEffects !== undefined ? freeze({
      meta, accounting, providerEffectAuthorities, providerApprovalLease, committedProviderEffects,
      uncertainAttempts: record.uncertainAttempts,
    }) : null
}

function parseRecovery(value: unknown): RuntimeOperationalTelemetry['recoveryTransient'] | null {
  const record = exactRecord(value, [
    'meta', 'status', 'observedOutboxRecoveriesInGeneration', 'droppedEventCount', 'counterSaturated',
  ])
  if (!record || !isOneOf(record.status, recoveryStatuses)
    || !isNullableSafeU64(record.observedOutboxRecoveriesInGeneration)
    || !isSafeU64(record.droppedEventCount) || typeof record.counterSaturated !== 'boolean') return null
  const meta = parseMeta(record.meta)
  return meta ? freeze({
    meta,
    status: record.status,
    observedOutboxRecoveriesInGeneration: record.observedOutboxRecoveriesInGeneration,
    droppedEventCount: record.droppedEventCount,
    counterSaturated: record.counterSaturated,
  }) : null
}

function parseMeta(value: unknown): TelemetrySectionMeta | null {
  const record = exactRecord(value, ['observedAtUnixSeconds', 'freshness', 'completeness'])
  return record && isSafeU64(record.observedAtUnixSeconds) && isOneOf(record.freshness, freshness)
    && isOneOf(record.completeness, completeness) ? freeze({
      observedAtUnixSeconds: record.observedAtUnixSeconds,
      freshness: record.freshness,
      completeness: record.completeness,
    }) : null
}

function parseAccounting(value: unknown): RuntimeOperationalTelemetry['durable']['accounting'] | null {
  const record = exactRecord(value, ['tokens', 'costMicroUsd'])
  if (!record) return null
  const tokens = parseBudget(record.tokens)
  const costMicroUsd = parseBudget(record.costMicroUsd)
  return tokens && costMicroUsd ? freeze({ tokens, costMicroUsd }) : null
}

function parseBudget(value: unknown): RuntimeBudget | null {
  const record = exactRecord(value, ['limit', 'reserved', 'settled', 'remaining'])
  return record && isSafeU64(record.limit) && isSafeU64(record.reserved) && isSafeU64(record.settled)
    && isSafeU64(record.remaining) ? freeze({
      limit: record.limit, reserved: record.reserved, settled: record.settled, remaining: record.remaining,
    }) : null
}

function parseAggregate(value: unknown): ExpiryAggregate | null {
  const record = exactRecord(value, [
    'activeCount', 'expiredActiveCount', 'nearestUnexpiredExpiryUnixSeconds',
  ])
  return record && isSafeU64(record.activeCount) && isSafeU64(record.expiredActiveCount)
    && isNullableSafeU64(record.nearestUnexpiredExpiryUnixSeconds) ? freeze({
      activeCount: record.activeCount,
      expiredActiveCount: record.expiredActiveCount,
      nearestUnexpiredExpiryUnixSeconds: record.nearestUnexpiredExpiryUnixSeconds,
    }) : null
}

function parseNullable<T>(value: unknown, parse: (candidate: unknown) => T | null): T | null | undefined {
  if (value === null) return null
  return parse(value) ?? undefined
}

function exactRecord(value: unknown, keys: readonly string[]): RecordValue | null {
  return isRecord(value) && hasExactKeys(value, keys) ? value : null
}

function isRecord(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isOneOf<T extends string>(value: unknown, values: readonly T[]): value is T {
  return typeof value === 'string' && values.includes(value as T)
}

function freeze<T>(value: T): T {
  return Object.freeze(value)
}
