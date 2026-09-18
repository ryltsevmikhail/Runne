import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import {
  projectProviderQuotaSnapshot,
  type ProviderQuotaProjection,
} from '@/pages/providers/model/providerQuota'

import {
  isCredentialProvider,
  isProviderId,
  type ProviderCredentialProvider,
  type ProviderId,
} from './providerCatalog'

export { CREDENTIAL_PROVIDER_IDS, PROVIDER_CATALOG } from './providerCatalog'
export type { ProviderCredentialProvider, ProviderId } from './providerCatalog'
export type { ProviderQuotaProjection } from '@/pages/providers/model/providerQuota'

export type ProviderReadiness =
  | 'ready'
  | 'credential_missing'
  | 'credential_access_denied'
  | 'credential_identity_mismatch'
  | 'secure_store_unavailable'
  | 'not_selected'

export interface ProviderStatusSnapshot {
  readonly providerId: ProviderId
  readonly mode: string
  readonly profileId: string
  readonly profileDigest: string
  readonly readiness: ProviderReadiness
  readonly selected: boolean
}

export type ProviderCatalogSnapshot = Readonly<{
  providerId: string
  displayName: string
  protocol: 'responses' | 'chat_completions' | 'anthropic_messages' | 'gemini' | 'bedrock' | 'pi_messages' | 'multi_protocol'
  authOptions: readonly ('none' | 'api_key' | 'oauth' | 'aws')[]
  quota: 'subscription_window' | 'payg' | 'unqualified'
  implementation: 'catalog_only' | 'implemented' | 'live_qualified'
}>

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export type ProviderCredentialAction = 'pair' | 'revoke' | 'migrate_legacy' | 'verify'
export type ProviderCredentialIntentDisposition = 'pending' | 'completed' | 'cancelled' | 'unavailable'
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

export type ProviderCredentialState = 'configured' | 'missing' | 'access_denied' | 'unsupported' | 'unavailable'
export type ProviderCredentialReadiness = 'ready' | 'missing' | 'stale' | 'unavailable' | 'unsupported' | 'access_denied' | 'conflict' | 'invariant_failure'
export type ProviderCredentialVerificationState = 'not_verified' | 'local_verified' | 'remote_verified' | 'failed' | 'unsupported' | 'unavailable' | 'access_denied' | 'stale'
export type ProviderCredentialPendingOperation = 'pairing' | 'rotating' | 'revoking' | 'reconciling' | 'verifying'
export type ProviderCredentialDisposition = 'completed' | 'access_denied' | 'unsupported' | 'unavailable' | 'conflict' | 'invalid_request' | 'invariant_failure'

const credentialProjectionKeys = [
  'providerId', 'credentialState', 'readiness', 'lifecycleRevision', 'readinessRevision',
  'observedAt', 'verificationState', 'verificationRevision', 'pendingOperation',
  'cleanupPending', 'lastDisposition',
] as const

export async function getProviderStatus(
  invoke: Invoke = tauriInvoke,
): Promise<readonly ProviderStatusSnapshot[]> {
  const value = await invoke('get_provider_status')
  if (!Array.isArray(value) || !value.every(isProviderStatus)) {
    throw new Error('Invalid provider status')
  }
  const selected = value.filter(item => item.selected)
  if (selected.length !== 1 || new Set(value.map(item => item.providerId)).size !== value.length) {
    throw new Error('Invalid provider status selection')
  }
  return value
}

/** Fetches backend-authoritative provider metadata without credentials. */
export async function getProviderCatalog(
  invoke: Invoke = tauriInvoke,
): Promise<readonly ProviderCatalogSnapshot[]> {
  const value = await invoke('get_provider_catalog')
  if (!Array.isArray(value) || !value.every(isProviderCatalogSnapshot)) {
    throw new Error('Invalid provider catalog')
  }
  if (new Set(value.map(item => item.providerId)).size !== value.length) {
    throw new Error('Invalid provider catalog identities')
  }
  return value
}

/** Reads runtime-captured quota evidence; no provider refresh is initiated. */
export async function getProviderQuota(
  invoke: Invoke = tauriInvoke,
): Promise<readonly ProviderQuotaProjection[]> {
  const value = await invoke('get_provider_quota')
  if (!Array.isArray(value)) throw new Error('Invalid provider quota')
  const projections = value.map(projectProviderQuotaSnapshot)
  if (new Set(projections.map(projection => projection.providerId)).size !== projections.length) {
    throw new Error('Invalid provider quota identities')
  }
  return projections
}

export async function requestProviderCredentialIntent(
  provider: ProviderCredentialProvider,
  action: ProviderCredentialAction,
  expectedRevision: number,
  rendererGeneration: number,
  invoke: Invoke = tauriInvoke,
): Promise<ProviderCredentialIntentDisposition> {
  if (!isCredentialProvider(provider)) throw new Error('Invalid provider credential provider')
  if (action !== 'pair' && action !== 'revoke' && action !== 'migrate_legacy' && action !== 'verify') {
    throw new Error('Invalid provider credential action')
  }
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision <= 0) {
    throw new Error('Invalid expected lifecycle revision')
  }
  if (!Number.isSafeInteger(rendererGeneration) || rendererGeneration <= 0) {
    throw new Error('Invalid renderer generation')
  }
  return parseIntentDisposition(await invoke('request_provider_credential_intent', {
    request: {
      provider, action, expectedRevision, rendererGeneration,
      ...(action === 'verify' ? { verificationKind: 'remote' } : {}),
    },
  }))
}

/** Fetches the closed V2 renderer projection; credentials never cross this boundary. */
export async function getProviderCredentialEnrollmentStatus(
  provider: ProviderCredentialProvider,
  invoke: Invoke = tauriInvoke,
): Promise<ProviderCredentialProjection> {
  if (!isCredentialProvider(provider)) throw new Error('Invalid provider credential provider')
  return projectProviderCredentialSnapshot(await invoke('get_provider_credential_enrollment_status', { provider }))
}

/** Parses the exact safe V2 projection and rejects every non-renderer field. */
export function projectProviderCredentialSnapshot(value: unknown): ProviderCredentialProjection {
  if (!isRecord(value) || !hasExactCredentialProjectionKeys(value)
    || !isCredentialProvider(value.providerId)
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

function parseIntentDisposition(value: unknown): ProviderCredentialIntentDisposition {
  if (value !== 'pending' && value !== 'completed' && value !== 'cancelled' && value !== 'unavailable') {
    throw new Error('Invalid provider credential intent disposition')
  }
  return value
}

function isProviderStatus(value: unknown): value is ProviderStatusSnapshot {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const candidate = value as Record<string, unknown>
  const expected = ['providerId', 'mode', 'profileId', 'profileDigest', 'readiness', 'selected']
  if (Object.keys(candidate).length !== expected.length || expected.some(key => !(key in candidate))) return false
  return isProviderId(candidate.providerId)
    && typeof candidate.mode === 'string'
    && candidate.mode.length > 0
    && candidate.mode.length <= 128
    && typeof candidate.profileId === 'string'
    && candidate.profileId.length > 0
    && candidate.profileId.length <= 128
    && /^[0-9a-f]{64}$/.test(String(candidate.profileDigest))
    && isReadiness(candidate.readiness)
    && typeof candidate.selected === 'boolean'
    && (candidate.selected || candidate.readiness === 'not_selected')
}

function isProviderCatalogSnapshot(value: unknown): value is ProviderCatalogSnapshot {
  if (!isRecord(value)) return false
  const expected = ['providerId', 'displayName', 'protocol', 'authOptions', 'quota', 'implementation']
  if (Object.keys(value).length !== expected.length || expected.some(key => !(key in value))) return false
  return typeof value.providerId === 'string'
    && value.providerId.length > 0
    && isProviderId(value.providerId)
    && typeof value.displayName === 'string'
    && value.displayName.length > 0
    && isOneOf(value.protocol, ['responses', 'chat_completions', 'anthropic_messages', 'gemini', 'bedrock', 'pi_messages', 'multi_protocol'])
    && Array.isArray(value.authOptions)
    && value.authOptions.length > 0
    && value.authOptions.every(auth => isOneOf(auth, ['none', 'api_key', 'oauth', 'aws']))
    && isOneOf(value.quota, ['subscription_window', 'payg', 'unqualified'])
    && isOneOf(value.implementation, ['catalog_only', 'implemented', 'live_qualified'])
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactCredentialProjectionKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value)
  return keys.length === credentialProjectionKeys.length && credentialProjectionKeys.every(key => key in value)
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

function isReadiness(value: unknown): value is ProviderReadiness {
  return value === 'ready'
    || value === 'credential_missing'
    || value === 'credential_access_denied'
    || value === 'credential_identity_mismatch'
    || value === 'secure_store_unavailable'
    || value === 'not_selected'
}
