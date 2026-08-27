import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type ProviderReadiness =
  | 'ready'
  | 'credential_missing'
  | 'credential_access_denied'
  | 'credential_identity_mismatch'
  | 'secure_store_unavailable'
  | 'not_selected'

export interface ProviderStatusSnapshot {
  readonly providerId: 'deterministic' | 'openai' | 'deepseek'
  readonly mode: string
  readonly profileId: string
  readonly profileDigest: string
  readonly readiness: ProviderReadiness
  readonly selected: boolean
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export type ProviderCredentialProvider = 'openai' | 'deepseek'
export type ProviderCredentialAction = 'pair' | 'revoke' | 'migrate_legacy'
export type ProviderCredentialIntentDisposition = 'pending' | 'cancelled' | 'unavailable'

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

export async function requestProviderCredentialIntent(
  provider: ProviderCredentialProvider,
  action: ProviderCredentialAction,
  expectedRevision: number,
  invoke: Invoke = tauriInvoke,
): Promise<ProviderCredentialIntentDisposition> {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision <= 0) {
    throw new Error('Invalid expected lifecycle revision')
  }
  return parseIntentDisposition(await invoke('request_provider_credential_intent', {
    request: { provider, action, expectedRevision },
  }))
}

function parseIntentDisposition(value: unknown): ProviderCredentialIntentDisposition {
  if (value !== 'pending' && value !== 'cancelled' && value !== 'unavailable') {
    throw new Error('Invalid provider credential intent disposition')
  }
  return value
}

function isProviderStatus(value: unknown): value is ProviderStatusSnapshot {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const candidate = value as Record<string, unknown>
  const expected = ['providerId', 'mode', 'profileId', 'profileDigest', 'readiness', 'selected']
  if (Object.keys(candidate).length !== expected.length || expected.some(key => !(key in candidate))) return false
  return (candidate.providerId === 'deterministic'
      || candidate.providerId === 'openai'
      || candidate.providerId === 'deepseek')
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

function isReadiness(value: unknown): value is ProviderReadiness {
  return value === 'ready'
    || value === 'credential_missing'
    || value === 'credential_access_denied'
    || value === 'credential_identity_mismatch'
    || value === 'secure_store_unavailable'
    || value === 'not_selected'
}
