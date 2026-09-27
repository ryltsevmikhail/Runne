import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'

export type RuntimeSessionStatus =
  | 'empty' | 'loading' | 'live' | 'stale' | 'reconnecting'
  | 'incompatible' | 'revoked' | 'fatal' | 'unavailable'

export interface RuntimeSessionSnapshot {
  readonly runtime: RuntimeConnectionState | null
  readonly status: RuntimeSessionStatus
  readonly canMutate: boolean
}

export function statusFor(
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

export function snapshot(
  runtime: RuntimeConnectionState | null,
  status: RuntimeSessionStatus,
): RuntimeSessionSnapshot {
  return { runtime, status, canMutate: status === 'live' }
}
