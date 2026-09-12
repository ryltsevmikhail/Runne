import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import type {
  ProviderCredentialAction,
  ProviderCredentialIntentDisposition,
  ProviderCredentialProjection,
  ProviderCredentialProvider,
  ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'

import ProvidersPage from './ProvidersPage.vue'

const statuses: readonly ProviderStatusSnapshot[] = [
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

function credentialProjection(provider: ProviderCredentialProvider): ProviderCredentialProjection {
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

type RecordedIntent = {
  provider: ProviderCredentialProvider
  action: ProviderCredentialAction
  expectedRevision: number
  rendererGeneration: number
}

function mountProvidersPage(overrides: {
  loadProviderStatus?: () => Promise<readonly ProviderStatusSnapshot[]>
  loadProviderCredentialEnrollmentStatus?: (provider: ProviderCredentialProvider) => Promise<ProviderCredentialProjection>
  requestCredentialIntent?: (provider: ProviderCredentialProvider, action: ProviderCredentialAction, expectedRevision: number, rendererGeneration: number) => Promise<ProviderCredentialIntentDisposition>
} = {}) {
  return mount(ProvidersPage, {
    props: {
      loadProviderStatus: overrides.loadProviderStatus ?? vi.fn(async () => statuses),
      loadProviderCredentialEnrollmentStatus: overrides.loadProviderCredentialEnrollmentStatus
        ?? (async (provider: ProviderCredentialProvider) => credentialProjection(provider)),
      acquireGeneration: async () => 42,
      requestCredentialIntent: overrides.requestCredentialIntent ?? (async () => 'pending'),
    },
  })
}

describe('providers page credential enrollment', () => {
  it('offers credential enrollment only on the openai and deepseek rows', async () => {
    const wrapper = mountProvidersPage()
    await flushPromises()

    const labels = wrapper.findAll('button').map(button => button.attributes('aria-label'))
    expect(labels).toEqual(['Enroll credential (openai)', 'Enroll credential (deepseek)'])
    expect(wrapper.text()).toContain('Enroll credential')
  })

  it('requests a pairing intent with the acquired generation and reloads statuses', async () => {
    const loadProviderStatus = vi.fn(async () => statuses)
    const intents: RecordedIntent[] = []
    const wrapper = mountProvidersPage({
      loadProviderStatus,
      requestCredentialIntent: async (provider, action, expectedRevision, rendererGeneration) => {
        intents.push({ provider, action, expectedRevision, rendererGeneration })
        return 'pending'
      },
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (deepseek)"]').trigger('click')
    await flushPromises()

    expect(intents).toEqual([{ provider: 'deepseek', action: 'pair', expectedRevision: 7, rendererGeneration: 42 }])
    expect(loadProviderStatus).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('Credential saved')
  })

  it('disables the enroll button while the intent is in flight', async () => {
    let resolveIntent: ((disposition: 'pending') => void) | undefined
    const wrapper = mountProvidersPage({
      requestCredentialIntent: () => new Promise<'pending'>(resolve => { resolveIntent = resolve }),
    })
    await flushPromises()

    const button = wrapper.get('button[aria-label="Enroll credential (openai)"]')
    await button.trigger('click')
    expect(button.attributes('disabled')).toBeDefined()

    resolveIntent?.('pending')
    await flushPromises()
    expect(wrapper.get('button[aria-label="Enroll credential (openai)"]').attributes('disabled')).toBeUndefined()
  })

  it('surfaces a closed disposition next to the row without a page alert', async () => {
    const wrapper = mountProvidersPage({ requestCredentialIntent: async () => 'cancelled' })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (deepseek)"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="status"]').text()).toBe('Enrollment failed: cancelled')
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('surfaces the closed rejection code when the intent is rejected', async () => {
    const wrapper = mountProvidersPage({
      requestCredentialIntent: async () => {
        throw new Error('provider_credential_intent_rejected')
      },
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (openai)"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="status"]').text()).toBe('Enrollment failed: provider_credential_intent_rejected')
  })

  it('reads a fresh credential status when the projection was unavailable before enrolling', async () => {
    let credentialCalls = 0
    const intents: RecordedIntent[] = []
    const wrapper = mountProvidersPage({
      loadProviderCredentialEnrollmentStatus: async (provider) => {
        credentialCalls += 1
        if (credentialCalls === 1) throw new Error('provider_credential_status_unavailable')
        return credentialProjection(provider)
      },
      requestCredentialIntent: async (provider, action, expectedRevision, rendererGeneration) => {
        intents.push({ provider, action, expectedRevision, rendererGeneration })
        return 'pending'
      },
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (deepseek)"]').trigger('click')
    await flushPromises()

    expect(intents).toEqual([{ provider: 'deepseek', action: 'pair', expectedRevision: 7, rendererGeneration: 42 }])
    expect(wrapper.text()).toContain('Credential saved')
  })
})
