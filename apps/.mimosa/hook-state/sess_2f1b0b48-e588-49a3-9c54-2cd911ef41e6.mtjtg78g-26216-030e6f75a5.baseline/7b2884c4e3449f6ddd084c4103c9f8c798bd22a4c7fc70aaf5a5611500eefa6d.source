import type { RuntimeFailureCode, RuntimeLifecycleStatus, RuntimeMode } from './bootstrap'

export type TelemetryFreshness = 'observed_in_current_cycle' | 'unavailable'
export type TelemetryCompleteness = 'complete' | 'partial' | 'unavailable'
export type RecoveryObservationStatus =
  | 'lower_bound_since_launch'
  | 'truncated_lower_bound_since_launch'
  | 'unavailable'
export type HostLifecycleEventStatus =
  | 'complete_since_app_core_start'
  | 'truncated_since_app_core_start'
  | 'unavailable'

export interface TelemetrySectionMeta {
  readonly observedAtUnixSeconds: number
  readonly freshness: TelemetryFreshness
  readonly completeness: TelemetryCompleteness
}

export interface RuntimeBudget {
  readonly limit: number
  readonly reserved: number
  readonly settled: number
  readonly remaining: number
}

export interface ExpiryAggregate {
  readonly activeCount: number
  readonly expiredActiveCount: number
  readonly nearestUnexpiredExpiryUnixSeconds: number | null
}

export interface RuntimeOperationalTelemetry {
  readonly schemaVersion: number
  readonly observedAtUnixSeconds: number
  readonly launchGeneration: number
  readonly durable: {
    readonly meta: TelemetrySectionMeta
    readonly accounting: { readonly tokens: RuntimeBudget, readonly costMicroUsd: RuntimeBudget } | null
    readonly providerEffectAuthorities: ExpiryAggregate | null
    readonly providerApprovalLease: ExpiryAggregate | null
    readonly committedProviderEffects: ExpiryAggregate | null
    readonly uncertainAttempts: number | null
  }
  readonly recoveryTransient: {
    readonly meta: TelemetrySectionMeta
    readonly status: RecoveryObservationStatus
    readonly observedOutboxRecoveriesInGeneration: number | null
    readonly droppedEventCount: number
    readonly counterSaturated: boolean
  }
}

export interface HostLifecycleEntry {
  readonly lifecycle: RuntimeLifecycleStatus
  readonly failure: RuntimeFailureCode | null
  readonly restartOrdinal: number | null
  readonly runtimeLaunchGeneration: number | null
  readonly observedAtUnixSeconds: number
}

export interface HostLifecycleEvent extends HostLifecycleEntry {
  readonly sequence: number
}

export interface OperationalTelemetrySnapshot {
  readonly schemaVersion: number
  readonly observedAtUnixSeconds: number
  readonly runtime: {
    readonly meta: TelemetrySectionMeta
    readonly snapshot: RuntimeOperationalTelemetry | null
  }
  readonly hostLifecycle: {
    readonly meta: TelemetrySectionMeta
    readonly runtimeMode: RuntimeMode
    readonly current: HostLifecycleEntry | null
    readonly events: readonly HostLifecycleEvent[] | null
    readonly eventStatus: HostLifecycleEventStatus
    readonly lastAllocatedSequence: number | null
    readonly producerDroppedEventCount: number
    readonly producerDropCounterSaturated: boolean
    readonly evictedEventCount: number
    readonly evictionCounterSaturated: boolean
  }
}
