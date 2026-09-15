import {
  isRuntimeConnectionState,
  type RuntimeConnectionState,
} from '@/shared/api/platform/bootstrap'

export type RuntimeSessionStatus =
  | 'empty'
  | 'loading'
  | 'live'
  | 'stale'
  | 'reconnecting'
  | 'incompatible'
  | 'revoked'
  | 'fatal'
  | 'unavailable'

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

// Automatic reconnect is contractually limited to recoverable transport states;
// terminal or explicit-resync conditions require an explicit policy action.
const TRANSIENT_STATES = new Set(['reconnecting'])
const REVOKED_STATES = new Set(['incompatible', 'revoked', 'fatal'])

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

  // Tickets are fenced by close/reopen and every establishment transition.
  function ticketFenced(ticket: number | undefined): boolean {
    return ticket !== undefined && ticket !== sessionGeneration
  }

  async function establish(): Promise<RuntimeSessionSnapshot> {
    const epoch = ++sessionEpoch
    sessionGeneration += 1
    closed = false
    let proven = false
    authenticated = false
    publish(snapshot(null, 'loading'))
    try {
      const connected = runtimeFrom(await dependencies.connect())
      if (epoch !== sessionEpoch) return current
      if (connected === null) {
        lastResetClass = 'terminal'
        return publish(snapshot(null, 'fatal'))
      }
      const connectedLive = connected === 'live'
      const runtime = runtimeFrom(await dependencies.loadBootstrap())
      if (epoch !== sessionEpoch) return current
      proven = connectedLive && runtime === 'live'
      authenticated = proven
      const latched = lastResetClass !== null && lastResetClass !== 'transient'
      const connectKlass = observationClass(connected)
      const recoverableBootstrap
        = runtime === 'live' || (runtime !== null && TRANSIENT_STATES.has(runtime))
      lastResetClass = proven
        ? null
        : latched
          ? lastResetClass
          : connectKlass === 'revoked' || connectKlass === 'unknown' || !recoverableBootstrap
            ? 'terminal'
            : 'transient'
      return publish(snapshot(runtime, statusFor(runtime, authenticated)))
    }
    catch {
      if (epoch !== sessionEpoch) return current
      authenticated = false
      lastResetClass = 'terminal'
      return publish(snapshot(null, 'unavailable'))
    }
    finally {
      if (proven && epoch === sessionEpoch) {
        automaticFailures = 0
      }
    }
  }

  // Manual connect/retry never waits for recovery; epochs fence late results.
  async function establishExclusively(): Promise<RuntimeSessionSnapshot> {
    const manualId = ++latestManualId
    pendingManuals.add(manualId)
    lastResetClass = null
    const closeSeq = closeSequence
    const resetSeq = proofResetGeneration
    if (recovery !== null) {
      const cancelled = recoveryCancel
      recovery = null
      recoveryOwner = null
      recoveryCancel = null
      sessionEpoch += 1
      if (cancelled !== null) cancelled.cancelled = true
    }
    try {
      if (closeSeq !== closeSequence || resetSeq !== proofResetGeneration) {
        return current
      }
      return await establish()
    }
    finally {
      pendingManuals.delete(manualId)
    }
  }

  // Recovery waits for the newest manual op; a hung older one never blocks.
  function newestManualPending(): boolean {
    return pendingManuals.has(latestManualId)
  }

  // Bounded automatic re-authentication after a transient disconnect; the
  // microtask delay keeps observeBootstrap's synchronous snapshot contract.
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
      // Invalidate in-flight attempts and unlink any pending recovery.
      sessionEpoch += 1
      closeSequence += 1
      proofResetGeneration += 1
      sessionGeneration += 1
      closed = true
      authenticated = false
      lastResetClass = null
      recovery = null
      recoveryOwner = null
      recoveryCancel = null
      publish(snapshot(null, 'unavailable'))
    },
    observeBootstrap(value, ticket) {
      const runtime = runtimeFrom(value)
      // Closed controllers and stale-generation reads are ignored.
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
        if (lastResetClass === null || lastResetClass === 'transient') {
          lastResetClass = 'transient'
        }
        return publish(snapshot(runtime, statusFor(runtime, false)))
      }
      // Terminal/resync: fence in-flight attempts, require explicit action.
      sessionEpoch += 1
      proofResetGeneration += 1
      authenticated = false
      lastResetClass = klass
      return publish(snapshot(runtime, statusFor(runtime, false)))
    },
  }
}

function runtimeFrom(value: unknown): RuntimeConnectionState | null {
  if (isRuntimeConnectionState(value)) {
    return value
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null
  }
  const runtime = (value as Record<string, unknown>).runtime
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
