export type ProviderCredentialProjection = Readonly<{
  providerId: ProviderCredentialProvider
  credentialState: ProviderCredentialState
  readiness: ProviderCredentialReadiness
  lifecycleRevision: number
  readinessRevision: number
  observedAt: number
  verificationState: ProviderCredentialVerificationState
  verificationRevision: number
  pendingOperation: ProviderCredentialPendingOperation | null
  cleanupPending: boolean
  lastDisposition: ProviderCredentialDisposition | null
}>

type ProviderCredentialProvider = 'openai' | 'deepseek'
type ProviderCredentialState = 'configured' | 'missing' | 'access_denied' | 'unsupported' | 'unavailable'
type ProviderCredentialReadiness = 'ready' | 'missing' | 'stale' | 'unavailable' | 'unsupported' | 'access_denied' | 'conflict' | 'invariant_failure'
type ProviderCredentialVerificationState = 'not_verified' | 'local_verified' | 'remote_verified' | 'failed' | 'unsupported' | 'unavailable' | 'access_denied' | 'stale'
type ProviderCredentialPendingOperation = 'pairing' | 'rotating' | 'revoking' | 'reconciling' | 'verifying'
type ProviderCredentialDisposition = 'completed' | 'access_denied' | 'unsupported' | 'unavailable' | 'conflict' | 'invalid_request' | 'invariant_failure'

const projectionKeys = [
  'providerId',
  'credentialState',
  'readiness',
  'lifecycleRevision',
  'readinessRevision',
  'observedAt',
  'verificationState',
  'verificationRevision',
  'pendingOperation',
  'cleanupPending',
  'lastDisposition',
] as const

/** Parses the exact safe V2 projection and rejects every non-renderer field. */
export function projectProviderCredentialSnapshot(value: unknown): ProviderCredentialProjection {
  if (!isRecord(value) || !hasExactKeys(value)
    || !isOneOf(value.providerId, ['openai', 'deepseek'])
    || !isOneOf(value.credentialState, ['configured', 'missing', 'access_denied', 'unsupported', 'unavailable'])
    || !isOneOf(value.readiness, ['ready', 'missing', 'stale', 'unavailable', 'unsupported', 'access_denied', 'conflict', 'invariant_failure'])
    || !isPositiveInteger(value.lifecycleRevision)
    || !isPositiveInteger(value.readinessRevision)
    || !isNonNegativeInteger(value.observedAt)
    || !isOneOf(value.verificationState, ['not_verified', 'local_verified', 'remote_verified', 'failed', 'unsupported', 'unavailable', 'access_denied', 'stale'])
    || !isNonNegativeInteger(value.verificationRevision)
    || !isNullableOneOf(value.pendingOperation, ['pairing', 'rotating', 'revoking', 'reconciling', 'verifying'])
    || typeof value.cleanupPending !== 'boolean'
    || !isNullableOneOf(value.lastDisposition, ['completed', 'access_denied', 'unsupported', 'unavailable', 'conflict', 'invalid_request', 'invariant_failure'])) {
    throw new Error('Invalid provider credential projection')
  }
  return value as ProviderCredentialProjection
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value)
  return keys.length === projectionKeys.length && projectionKeys.every(key => key in value)
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isNullableOneOf<T extends string>(value: unknown, values: readonly T[]): value is T | null {
  return value === null || isOneOf(value, values)
}

function isOneOf<T extends string>(value: unknown, values: readonly T[]): value is T {
  return typeof value === 'string' && values.includes(value as T)
}
