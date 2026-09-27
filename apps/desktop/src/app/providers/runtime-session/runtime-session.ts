import {
  isRuntimeConnectionState,
  type RuntimeConnectionState,
} from '@/shared/api/platform/bootstrap'
import { REVOKED_STATES, TRANSIENT_STATES } from './runtime-session-states'
import { connectThroughTransientWindow } from './transient-connect'

export type RuntimeSessionStatus =
  | 'empty' | 'loading' | 'live' | 'stale' | 'reconnecting'
  | 'incompatible' | 'revoked' | 'fatal' | 'unavailable'

export interface RuntimeSessionSnapshot {
  readonly runtime: RuntimeConnectionState | null
  readonly status: RuntimeSessionStatus
  readonly canMutate: boolean
}

export interface RuntimeSessionPort {
  snapshot(): RuntimeSessionSnapshot
  connect(): Promise<RuntimeSessionSnapshot>
  retry(): Promise<RuntimeSessionSnapshot>
  close(): Promise<void>
}

export interface RuntimeSessionController extends RuntimeSessionPort {
  observeBootstrap(value: unknown, ticket?: number): RuntimeSessionSnapshot
  sessionTicket(): number
  ticketFenced(ticket: number | undefined): boolean
}

interface RuntimeSessionDependencies {
  readonly connect: () => Promise<unknown>
  readonly loadBootstrap: () => Promise<unknown>
}

const MAX_AUTOMATIC_RECOVERIES = 3
const SETTLE_WAITS = 20
const SETTLE_DELAY_MS = 500

export function createRuntimeSessionPort(
  dependencies: RuntimeSessionDependencies,
): RuntimeSessionPort {
  return createRuntimeSessionController(dependencies)
}

export function createRuntimeSessionController(
  dependencies: RuntimeSessionDependencies,
): RuntimeSessionController {
  let authenticated = false
  let current = snapshot(null, 'empty')
  let recovery: Promise<RuntimeSessionSnapshot> | null = null
  let recoveryOwner: Promise<RuntimeSessionSnapshot> | null = null
  let recoveryCancel: { cancelled: boolean } | null = null
  let automaticFailures = 0
  let latestManualId = 0
  const pendingManuals = new Set<number>()
  let proofResetGeneration = 0
  let lastResetClass: string | null = null
  let closeSequence = 0
  let sessionEpoch = 0
  let sessionGeneration = 0
  let closed = true

  function observationClass(runtime: string | null): string {
    if (runtime === 'live') return 'live'
    if (runtime !== null && TRANSIENT_STATES.has(runtime)) return 'transient'
    if (runtime !== null && REVOKED_STATES.has(runtime)) return 'revoked'
    return 'unknown'
  }

  function publish(next: RuntimeSessionSnapshot): RuntimeSessionSnapshot {
    current = next
    return next
  }

  function ticketFenced(ticket: number | undefined): boolean {
    return ticket !== undefined && ticket !== sessionGeneration
  }

  async function establish(manual = false): Promise<RuntimeSessionSnapshot> {
    const epoch = ++sessionEpoch
    sessionGeneration += 1
    closed = false
    let proven = false
    authenticated = false
    if (manual) publish(snapshot(null, 'loading'))
    try {
      const connection = await connectThroughTransientWindow(
        dependencies.connect,
        () => epoch === sessionEpoch,
        () => new Promise(resolve => setTimeout(resolve, SETTLE_DELAY_MS)),
        manual ? 0 : SETTLE_WAITS,
      )
      if (epoch !== sessionEpoch || connection.kind === 'cancelled') return current
      const connected = runtimeFrom(connection.value)
      if (connected === null) {
        lastResetClass = 'terminal'
        return publish(snapshot(null, 'fatal'))
      }
      const connectedLive = connected === 'live'
      const connectKlass = observationClass(connected)
      if (connectKlass === 'revoked' || connectKlass === 'unknown') {
        if (lastResetClass === null || lastResetClass === 'transient') {
          lastResetClass = 'terminal'
        }
      }
      let runtime = runtimeFrom(await dependencies.loadBootstrap())
      if (epoch !== sessionEpoch) return current
      // The protected host may expose any valid handshake/recovery stage while
      // a session rotation settles. Re-read bounded before deciding readiness.
      let waits = 0
      while (runtime !== null && TRANSIENT_STATES.has(runtime)
        && waits < SETTLE_WAITS && epoch === sessionEpoch) {
        waits += 1
        await new Promise(resolve => setTimeout(resolve, SETTLE_DELAY_MS))
        if (epoch !== sessionEpoch) return current
        runtime = runtimeFrom(await dependencies.loadBootstrap())
      }
      proven = connectedLive && runtime === 'live'
      authenticated = proven
      const latched = lastResetClass !== null && lastResetClass !== 'transient'
      const recoverableBootstrap
        = runtime === 'live' || (runtime !== null && TRANSIENT_STATES.has(runtime))
      lastResetClass = proven
        ? null
        : latched
          ? lastResetClass
          : connectKlass === 'revoked' || connectKlass === 'unknown' || !recoverableBootstrap
            ? 'terminal'
            : 'transient'
      if (manual && (proven || lastResetClass === 'transient')) automaticFailures = 0
      return publish(snapshot(runtime, statusFor(runtime, authenticated)))
    }
    catch (error) {
      if (epoch !== sessionEpoch) return current
      authenticated = false
      const disposition = (error as { disposition?: unknown } | null | undefined)?.disposition
      if (disposition === 'transient') {
        if (manual) automaticFailures = 0
        return manual ? publish(snapshot(null, 'unavailable')) : current
      }
      lastResetClass = 'terminal'
      return publish(snapshot(null, manual ? 'unavailable' : 'fatal'))
    }
    finally {
      if (proven && epoch === sessionEpoch) automaticFailures = 0
    }
  }

  async function establishExclusively(): Promise<RuntimeSessionSnapshot> {
    const manualId = ++latestManualId
    pendingManuals.add(manualId)
    lastResetClass = null
    const closeSeq = closeSequence
    const resetSeq = proofResetGeneration
    if (recovery !== null) {
      const cancelled = recoveryCancel
      recovery = recoveryOwner = recoveryCancel = null
      sessionEpoch += 1
      if (cancelled !== null) cancelled.cancelled = true
    }
    try {
      if (closeSeq !== closeSequence || resetSeq !== proofResetGeneration) {
        return current
      }
      return await establish(true)
    }
    finally {
      pendingManuals.delete(manualId)
    }
  }

  function newestManualPending(): boolean {
    return pendingManuals.has(latestManualId)
  }

  function scheduleRecovery(): void {
    if (
      closed
      || newestManualPending()
      || recovery !== null
      || automaticFailures >= MAX_AUTOMATIC_RECOVERIES
      || (lastResetClass !== null && lastResetClass !== 'transient')
    ) {
      return
    }
    const cancel = { cancelled: false, started: false }
    const resetSeq = proofResetGeneration
    const run = Promise.resolve().then(() => {
      if (
        cancel.cancelled
        || closed
        || authenticated
        || newestManualPending()
        || resetSeq !== proofResetGeneration
      ) {
        return current
      }
      cancel.started = true
      return establish()
    })
    recovery = run
    recoveryOwner = run
    recoveryCancel = cancel
    void run
      .then((result) => {
        if (recoveryOwner === run && cancel.started && result.status !== 'live') {
          automaticFailures += 1
        }
      })
      .finally(() => {
        if (recoveryOwner === run) {
          recovery = null
          recoveryOwner = null
          recoveryCancel = null
        }
      })
  }

  return {
    snapshot: () => current,
    sessionTicket: () => sessionGeneration,
    ticketFenced,
    connect: () => establishExclusively(),
    retry: () => establishExclusively(),
    async close() {
      sessionEpoch += 1
      closeSequence += 1
      proofResetGeneration += 1
      sessionGeneration += 1
      closed = true
      authenticated = false
      lastResetClass = null
      recovery = recoveryOwner = recoveryCancel = null
      publish(snapshot(null, 'unavailable'))
    },
    observeBootstrap(value, ticket) {
      const runtime = runtimeFrom(value)
      if (closed || ticketFenced(ticket)) {
        return current
      }
      const klass = observationClass(runtime)
      if (klass === 'live') {
        if (!authenticated) {
          scheduleRecovery()
        }
        return publish(snapshot(runtime, statusFor(runtime, authenticated)))
      }
      if (klass === 'transient') {
        authenticated = false
        // A transient window itself triggers the bounded recovery.
        scheduleRecovery()
        return publish(snapshot(runtime, statusFor(runtime, false)))
      }
      sessionEpoch += 1
      proofResetGeneration += 1
      authenticated = false
      lastResetClass = klass
      return publish(snapshot(runtime, statusFor(runtime, false)))
    },
  }
}

function runtimeFrom(value: unknown): RuntimeConnectionState | null {
  if (isRuntimeConnectionState(value)) return value
  const runtime = typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>).runtime
    : null
  return isRuntimeConnectionState(runtime) ? runtime : null
}

function statusFor(
  runtime: RuntimeConnectionState | null,
  authenticated: boolean,
): RuntimeSessionStatus {
  if (runtime === 'live') {
    return authenticated ? 'live' : 'stale'
  }
  switch (runtime) {
    case 'unconfigured': return 'empty'
    case 'reconnecting': return 'reconnecting'
    case 'incompatible': return 'incompatible'
    case 'revoked': return 'revoked'
    case 'fatal': return 'fatal'
    case 'profile_loaded':
    case 'peer_verified':
    case 'bootstrap_proved':
    case 'authenticated':
    case 'reconciling':
    case 'resync_required': return 'stale'
    case null: return 'fatal'
  }
}

function snapshot(
  runtime: RuntimeConnectionState | null,
  status: RuntimeSessionStatus,
): RuntimeSessionSnapshot {
  return { runtime, status, canMutate: status === 'live' }
}
