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
  observeBootstrap(value: unknown): RuntimeSessionSnapshot
}

interface RuntimeSessionDependencies {
  readonly connect: () => Promise<unknown>
  readonly loadBootstrap: () => Promise<unknown>
}

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

  async function establish(): Promise<RuntimeSessionSnapshot> {
    authenticated = false
    current = snapshot(null, 'loading')
    try {
      const connected = runtimeFrom(await dependencies.connect())
      if (connected === null) {
        current = snapshot(null, 'fatal')
        return current
      }
      authenticated = connected === 'live'
      const runtime = runtimeFrom(await dependencies.loadBootstrap())
      if (runtime !== 'live') {
        authenticated = false
      }
      current = snapshot(runtime, statusFor(runtime, authenticated))
    }
    catch {
      authenticated = false
      current = snapshot(null, 'unavailable')
    }
    return current
  }

  return {
    snapshot: () => current,
    connect: establish,
    retry: establish,
    async close() {
      authenticated = false
      current = snapshot(null, 'unavailable')
    },
    observeBootstrap(value) {
      const runtime = runtimeFrom(value)
      if (runtime !== 'live') {
        authenticated = false
      }
      current = snapshot(runtime, statusFor(runtime, authenticated))
      return current
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
