import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import type {
  ProviderCredentialProjection,
  ProviderCredentialProvider,
  ProviderQuotaProjection,
  ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'

import ProvidersPage from './ProvidersPage.vue'

const statuses: readonly ProviderStatusSnapshot[] = [
  {
    providerId: 'deterministic', mode: 'deterministic_local_v1', profileId: 'deterministic',
    profileDigest: '1'.repeat(64), readiness: 'ready', selected: true,
  },
  {
    providerId: 'zai', mode: 'zai_coding_v1', profileId: 'zai-coding',
    profileDigest: '2'.repeat(64), readiness: 'not_selected', selected: false,
  },
]

function credential(providerId: ProviderCredentialProvider): ProviderCredentialProjection {
  return {
    providerId, credentialState: 'missing', readiness: 'missing', lifecycleRevision: 1,
    readinessRevision: 1, observedAt: 1, verificationState: 'not_verified',
    verificationRevision: 0, pendingOperation: null, cleanupPending: false, lastDisposition: null,
  }
}

function configuredCredential(providerId: ProviderCredentialProvider): ProviderCredentialProjection {
  return { ...credential(providerId), credentialState: 'configured', readiness: 'ready' }
}

function mountQuota(quota: ProviderQuotaProjection) {
  return mount(ProvidersPage, {
    props: {
      loadProviderStatus: async () => statuses,
      loadProviderCatalog: async () => [],
      loadProviderQuota: async () => [quota],
      loadProviderCredentialEnrollmentStatus: async provider => credential(provider),
    },
  })
}

describe('ProvidersPage percentage-only quota', () => {
  it('renders percentage-only windows without counters or units', async () => {
    const wrapper = mountQuota({
      providerId: 'zai', source: 'provider_reported', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'unknown', windows: [
        { kind: 'FiveHourTime', used: null, limit: null, remaining: null, percentUsed: 50, resetAt: null },
        { kind: 'WeeklyTime', used: null, limit: null, remaining: null, percentUsed: 0, resetAt: null },
      ],
    })
    await flushPromises()

    const text = wrapper.get('[data-provider-id="zai"] [data-quota="true"]').text()
    expect(text).toContain('Five-hour window: 50% used; reset: unknown')
    expect(text).toContain('Weekly window: 0% used; reset: unknown')
    expect(text).not.toMatch(/tokens|credits|requests|\d+\/\d+/)
  })

  it('keeps 100% exhausted and does not use a window reset as aggregate reset', async () => {
    const wrapper = mountQuota({
      providerId: 'zai', source: 'provider_reported', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'exhausted', windows: [{
        kind: 'MonthlyTime', used: null, limit: null, remaining: null, percentUsed: 100, resetAt: 20,
      }],
    })
    await flushPromises()

    const text = wrapper.get('[data-provider-id="zai"] [data-quota="true"]').text()
    expect(text).toContain('aggregate reset is unknown')
    expect(text).toContain('Monthly window: 100% used; reset:')
    expect(text).not.toContain('1700000000')
  })

  it('does not let a quota load started before rotation restore the old value', async () => {
    let quotaCall = 0
    let resolveOld: ((value: readonly ProviderQuotaProjection[]) => void) | undefined
    const oldQuota: ProviderQuotaProjection = {
      providerId: 'zai', source: 'provider_reported', unit: 'credits',
      used: 9, limit: 10, remaining: 1, resetAt: null, observedAt: 12,
      availability: 'known', windows: [],
    }
    const newQuota: ProviderQuotaProjection = {
      ...oldQuota, used: 1, remaining: 9, observedAt: 13,
    }
    const loadProviderQuota = vi.fn(() => {
      quotaCall += 1
      if (quotaCall === 2) {
        return new Promise<readonly ProviderQuotaProjection[]>(resolve => { resolveOld = resolve })
      }
      return Promise.resolve<readonly ProviderQuotaProjection[]>([quotaCall === 3 ? newQuota : oldQuota])
    })
    const wrapper = mount(ProvidersPage, {
      props: {
        loadProviderStatus: async () => statuses,
        loadProviderCatalog: async () => [],
        loadProviderQuota,
        loadProviderCredentialEnrollmentStatus: async provider => configuredCredential(provider),
        acquireGeneration: async () => 42,
        requestCredentialIntent: async () => 'pending',
      },
    })
    await flushPromises()

    type PageControls = {
      loadStatuses: () => Promise<void>
      changeCredential: (provider: 'zai', action: 'verify') => Promise<void>
    }
    const controls = wrapper.vm as unknown as PageControls
    const oldLoad = controls.loadStatuses()
    await flushPromises()
    expect(resolveOld).toBeDefined()
    await controls.changeCredential('zai', 'verify')
    const newLoad = controls.loadStatuses()
    resolveOld?.([oldQuota])
    await Promise.all([oldLoad, newLoad])
    await flushPromises()

    expect(wrapper.get('[data-provider-id="zai"] [data-quota="true"]').text()).toContain('9/10')
    expect(wrapper.get('[data-provider-id="zai"] [data-quota="true"]').text()).not.toContain('1/10')
  })
})
