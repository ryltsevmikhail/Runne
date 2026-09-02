import { describe, expect, it } from 'vitest'

import { getOperationalTelemetry } from './operational-telemetry'

function observedMeta(): Record<string, unknown> {
  return {
    observedAtUnixSeconds: 10,
    freshness: 'observed_in_current_cycle',
    completeness: 'complete',
  }
}

function validTelemetry(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    observedAtUnixSeconds: 10,
    runtime: {
      meta: observedMeta(),
      snapshot: {
        schemaVersion: 1,
        observedAtUnixSeconds: 10,
        launchGeneration: 1,
        durable: {
          meta: observedMeta(),
          accounting: {
            tokens: { limit: 10, reserved: 2, settled: 3, remaining: 5 },
            costMicroUsd: { limit: 10, reserved: 2, settled: 3, remaining: 5 },
          },
          providerEffectAuthorities: {
            activeCount: 1,
            expiredActiveCount: 0,
            nearestUnexpiredExpiryUnixSeconds: 11,
          },
          providerApprovalLease: {
            activeCount: 0,
            expiredActiveCount: 0,
            nearestUnexpiredExpiryUnixSeconds: null,
          },
          committedProviderEffects: {
            activeCount: 0,
            expiredActiveCount: 0,
            nearestUnexpiredExpiryUnixSeconds: null,
          },
          uncertainAttempts: 0,
        },
        recoveryTransient: {
          meta: observedMeta(),
          status: 'lower_bound_since_launch',
          observedOutboxRecoveriesInGeneration: 0,
          droppedEventCount: 0,
          counterSaturated: false,
        },
      },
    },
    hostLifecycle: {
      meta: observedMeta(),
      runtimeMode: 'bundled',
      current: {
        lifecycle: 'starting',
        failure: null,
        restartOrdinal: 0,
        runtimeLaunchGeneration: 0,
        observedAtUnixSeconds: 10,
      },
      events: [{
        sequence: 1,
        lifecycle: 'starting',
        failure: null,
        restartOrdinal: 0,
        runtimeLaunchGeneration: 0,
        observedAtUnixSeconds: 10,
      }],
      eventStatus: 'complete_since_app_core_start',
      lastAllocatedSequence: 1,
      producerDroppedEventCount: 0,
      producerDropCounterSaturated: false,
      evictedEventCount: 0,
      evictionCounterSaturated: false,
    },
  }
}

type Mutation = readonly [string, (wire: Record<string, unknown>) => void]

function record(value: unknown): Record<string, unknown> {
  return value as Record<string, unknown>
}

function get(wire: Record<string, unknown>, path: readonly string[]): unknown {
  return path.reduce<unknown>((value, key) => record(value)[key], wire)
}

function set(wire: Record<string, unknown>, path: readonly string[], value: unknown): void {
  const key = path.at(-1)
  if (key === undefined) throw new Error('mutation path is empty')
  record(get(wire, path.slice(0, -1)))[key] = value
}

function remove(wire: Record<string, unknown>, path: readonly string[]): void {
  const key = path.at(-1)
  if (key === undefined) throw new Error('mutation path is empty')
  delete record(get(wire, path.slice(0, -1)))[key]
}

const invalidMutations: readonly Mutation[] = [
  ['top-level extra key', wire => set(wire, ['debug'], true)],
  ['top-level missing key', wire => remove(wire, ['runtime'])],
  ['section extra key', wire => set(wire, ['runtime', 'extra'], true)],
  ['section metadata extra key', wire => set(wire, ['hostLifecycle', 'meta', 'extra'], true)],
  ['current extra key', wire => set(wire, ['hostLifecycle', 'current', 'path'], '/private')],
  ['event missing key', wire => remove(wire, ['hostLifecycle', 'events', '0', 'sequence'])],
  ['nested snapshot extra key', wire => set(wire, ['runtime', 'snapshot', 'durable', 'token'], 'secret')],
  ['nested aggregate missing key', wire => remove(wire, [
    'runtime', 'snapshot', 'durable', 'accounting', 'tokens', 'remaining',
  ])],
  ['unknown freshness enum', wire => set(wire, ['runtime', 'meta', 'freshness'], 'stale')],
  ['unknown completeness enum', wire => set(wire, ['hostLifecycle', 'meta', 'completeness'], 'unknown')],
  ['unknown lifecycle enum', wire => set(wire, ['hostLifecycle', 'current', 'lifecycle'], 'compromised')],
  ['unknown event status enum', wire => set(wire, ['hostLifecycle', 'eventStatus'], 'partial')],
  ['unknown recovery enum', wire => set(wire, ['runtime', 'snapshot', 'recoveryTransient', 'status'], 'estimated')],
  ['unknown failure enum', wire => set(wire, ['hostLifecycle', 'current', 'failure'], 'raw_error')],
  ['unsafe counter', wire => set(wire, ['hostLifecycle', 'evictedEventCount'], Number.MAX_SAFE_INTEGER + 1)],
  ['negative counter', wire => set(wire, ['runtime', 'snapshot', 'launchGeneration'], -1)],
  ['malformed nullable timestamp', wire => set(wire, [
    'runtime', 'snapshot', 'durable', 'providerApprovalLease', 'nearestUnexpiredExpiryUnixSeconds',
  ], 'later')],
  ['overflow event array', (wire) => {
    const event = get(wire, ['hostLifecycle', 'events', '0'])
    set(wire, ['hostLifecycle', 'events'], Array.from({ length: 65 }, () => event))
  }],
  ['section metadata timestamp differs from the top-level timestamp', wire => set(
    wire, ['runtime', 'meta', 'observedAtUnixSeconds'], 11,
  )],
  ['invalid observed metadata combination', wire => set(
    wire, ['runtime', 'meta', 'completeness'], 'unavailable',
  )],
  ['runtime snapshot is absent despite current complete metadata', wire => set(
    wire, ['runtime', 'snapshot'], null,
  )],
  ['runtime snapshot is present despite unavailable metadata', wire => {
    set(wire, ['runtime', 'meta', 'freshness'], 'unavailable')
    set(wire, ['runtime', 'meta', 'completeness'], 'unavailable')
  }],
  ['runtime launch generation is zero', wire => set(
    wire, ['runtime', 'snapshot', 'launchGeneration'], 0,
  )],
  ['runtime budget does not balance', wire => set(
    wire, ['runtime', 'snapshot', 'durable', 'accounting', 'tokens', 'remaining'], 4,
  )],
  ['expiry aggregate includes an expired nearest expiry', wire => set(
    wire, ['runtime', 'snapshot', 'durable', 'providerEffectAuthorities', 'nearestUnexpiredExpiryUnixSeconds'], 10,
  )],
  ['durable completeness disagrees with its present fields', wire => set(
    wire, ['runtime', 'snapshot', 'durable', 'uncertainAttempts'], null,
  )],
  ['lower-bound recovery reports dropped events', wire => set(
    wire, ['runtime', 'snapshot', 'recoveryTransient', 'droppedEventCount'], 1,
  )],
  ['unavailable recovery retains an observed count', wire => set(
    wire, ['runtime', 'snapshot', 'recoveryTransient', 'status'], 'unavailable',
  )],
  ['saturated recovery counter cannot be represented safely', wire => set(
    wire, ['runtime', 'snapshot', 'recoveryTransient', 'counterSaturated'], true,
  )],
  ['complete host event status has dropped events', wire => set(
    wire, ['hostLifecycle', 'producerDroppedEventCount'], 1,
  )],
  ['unavailable host metadata retains a current lifecycle', wire => {
    set(wire, ['hostLifecycle', 'meta', 'freshness'], 'unavailable')
    set(wire, ['hostLifecycle', 'meta', 'completeness'], 'unavailable')
  }],
  ['external host mode retains a bundled lifecycle tuple', wire => set(
    wire, ['hostLifecycle', 'runtimeMode'], 'external_local',
  )],
  ['configuration lifecycle has an unrelated failure code', wire => {
    set(wire, ['hostLifecycle', 'current', 'lifecycle'], 'configuration_required')
    set(wire, ['hostLifecycle', 'current', 'failure'], 'bundled_restart_exhausted')
  }],
]

describe('operational telemetry platform API', () => {
  it('accepts the exact current AppCore telemetry projection', async () => {
    const wire = validTelemetry()

    const snapshot = await getOperationalTelemetry(async () => wire)

    expect(snapshot).toMatchObject({ schemaVersion: 1, observedAtUnixSeconds: 10 })
    expect(snapshot).not.toBe(wire)
    wire.schemaVersion = 2
    expect(snapshot.schemaVersion).toBe(1)
  })

  it.each(invalidMutations)('rejects %s', async (_, mutate) => {
    const wire = structuredClone(validTelemetry())
    mutate(wire)

    await expect(getOperationalTelemetry(async () => wire)).rejects.toThrow(
      'Invalid operational telemetry response',
    )
  })
})
