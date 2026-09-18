import { mount } from '@vue/test-utils'
import { vi } from 'vitest'

import type {
  ProviderCatalogSnapshot,
  ProviderCredentialAction,
  ProviderCredentialIntentDisposition,
  ProviderCredentialProjection,
  ProviderCredentialProvider,
  ProviderQuotaProjection,
  ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'

import ProvidersPage from './ProvidersPage.vue'

export const statuses: readonly ProviderStatusSnapshot[] = [
  {
    providerId: 'deterministic',
    mode: 'deterministic_local_v1',
    profileId: 'deterministic',
    profileDigest: '1'.repeat(64),
    readiness: 'ready',
    selected: true,
  },
  {
    providerId: 'openai',
    mode: 'openai_responses_text_v1',
    profileId: 'openai-responses-text-v1',
    profileDigest: '2'.repeat(64),
    readiness: 'not_selected',
    selected: false,
  },
  {
    providerId: 'deepseek',
    mode: 'deepseek_responses_text_v1',
    profileId: 'deepseek-responses-text-v1',
    profileDigest: '3'.repeat(64),
    readiness: 'not_selected',
    selected: false,
  },
]

export function credentialProjection(provider: ProviderCredentialProvider): ProviderCredentialProjection {
  return {
    providerId: provider,
    credentialState: 'missing',
    readiness: 'missing',
    lifecycleRevision: 7,
    readinessRevision: 1,
    observedAt: 9,
    verificationState: 'not_verified',
    verificationRevision: 0,
    pendingOperation: null,
    cleanupPending: false,
    lastDisposition: null,
  }
}

export type RecordedIntent = {
  provider: ProviderCredentialProvider
  action: ProviderCredentialAction
  expectedRevision: number
  rendererGeneration: number
}

export function mountProvidersPage(overrides: {
  loadProviderStatus?: () => Promise<readonly ProviderStatusSnapshot[]>
  loadProviderCatalog?: () => Promise<readonly ProviderCatalogSnapshot[]>
  loadProviderQuota?: () => Promise<readonly ProviderQuotaProjection[]>
  loadProviderCredentialEnrollmentStatus?: (provider: ProviderCredentialProvider) => Promise<ProviderCredentialProjection>
  requestCredentialIntent?: (provider: ProviderCredentialProvider, action: ProviderCredentialAction, expectedRevision: number, rendererGeneration: number) => Promise<ProviderCredentialIntentDisposition>
} = {}) {
  return mount(ProvidersPage, {
    props: {
      loadProviderStatus: overrides.loadProviderStatus ?? vi.fn(async () => statuses),
      loadProviderCatalog: overrides.loadProviderCatalog ?? (async () => []),
      loadProviderQuota: overrides.loadProviderQuota ?? (async () => []),
      loadProviderCredentialEnrollmentStatus: overrides.loadProviderCredentialEnrollmentStatus
        ?? (async (provider: ProviderCredentialProvider) => credentialProjection(provider)),
      acquireGeneration: async () => 42,
      requestCredentialIntent: overrides.requestCredentialIntent ?? (async () => 'pending'),
    },
  })
}
