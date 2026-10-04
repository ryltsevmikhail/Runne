import { flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import type { ProviderStatusSnapshot } from '@/shared/api/platform/providers'

import {
  credentialProjection,
  mountProvidersPage,
  statuses,
} from './ProvidersPage.test-support'
import type { RecordedIntent } from './ProvidersPage.test-support'

describe('providers page credential enrollment', () => {
  it('offers credential enrollment only on the openai and deepseek rows', async () => {
    const wrapper = mountProvidersPage()
    await flushPromises()

    const labels = wrapper.findAll('button').map(button => button.attributes('aria-label'))
    expect(labels).toEqual(['Enroll credential (openai)', 'Enroll credential (deepseek)'])
    expect(wrapper.text()).toContain('Enroll credential')
  })

  it('offers enrollment for the implemented extra Chat profiles', async () => {
    const extraStatuses: readonly ProviderStatusSnapshot[] = [...statuses,
      {
        providerId: 'fireworks', mode: 'chat_completions', profileId: 'fireworks',
        profileDigest: '4'.repeat(64), readiness: 'not_selected', selected: false,
      },
      {
        providerId: 'mistral', mode: 'chat_completions', profileId: 'mistral',
        profileDigest: '5'.repeat(64), readiness: 'not_selected', selected: false,
      },
      {
        providerId: 'opencode-go', mode: 'chat_completions', profileId: 'opencode-go',
        profileDigest: '6'.repeat(64), readiness: 'not_selected', selected: false,
      },
    ]
    const wrapper = mountProvidersPage({ loadProviderStatus: async () => extraStatuses })
    await flushPromises()

    expect(wrapper.findAll('button').map(button => button.attributes('aria-label'))).toEqual([
      'Enroll credential (openai)', 'Enroll credential (deepseek)',
      'Enroll credential (fireworks)', 'Enroll credential (mistral)',
      'Enroll credential (opencode-go)',
    ])
  })

  it('labels planned subscription providers while exposing protected enrollment', async () => {
    const wrapper = mountProvidersPage({
      loadProviderStatus: async () => [...statuses, {
        providerId: 'zai', mode: 'zai_coding_v1', profileId: 'zai-coding', profileDigest: '4'.repeat(64),
        readiness: 'not_selected', selected: false,
      }],
      loadProviderCatalog: async () => [{
        providerId: 'zai', displayName: 'Z.AI', protocol: 'chat_completions', authOptions: ['api_key'],
        quota: 'subscription_window', implementation: 'catalog_only',
      }],
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Z.AI')
    expect(wrapper.text()).toContain('Catalog entry is not runtime-qualified')
    expect(wrapper.text()).toContain('Provider subscription limits apply')
    expect(wrapper.findAll('button').map(button => button.attributes('aria-label')))
      .toContain('Enroll credential (zai)')
  })

  it('shows the background API-key profile as optional, separate-budget, and never fallback', async () => {
    const wrapper = mountProvidersPage({
      loadProviderStatus: async () => [...statuses, {
        providerId: 'openai-background', mode: 'openai_responses_background_text_v1',
        profileId: 'gocode-openai-responses-background-text/1', profileDigest: 'a'.repeat(64),
        readiness: 'not_selected', selected: false,
      }],
      loadProviderCatalog: async () => [{
        providerId: 'openai-background', displayName: 'OpenAI Background Responses',
        protocol: 'responses', authOptions: ['api_key'], quota: 'payg', implementation: 'catalog_only',
      }],
      loadProviderCredentialEnrollmentStatus: async provider => ({
        ...credentialProjection(provider),
        ...(provider === 'openai-background' ? { credentialState: 'configured' as const, readiness: 'ready' as const } : {}),
      }),
    })
    await flushPromises()

    const row = wrapper.get('[data-provider-id="openai-background"]')
    expect(row.text()).toContain('OpenAI Background Responses')
    expect(row.text()).toContain('Catalog entry is not runtime-qualified')
    expect(row.text()).toContain('Pairing only saves this separate API credential and budget')
    expect(row.text()).toContain('GET /v1/runtime/profile')
    expect(row.text()).toContain('profileId and profileDigest')
    expect(row.text()).toContain('new /v2/task-runs/submit request')
    expect(row.text()).toContain('Not selected')
    expect(row.find('button[aria-label="Refresh quota (openai-background)"]').exists()).toBe(false)
    expect(row.find('button[aria-label="Rotate credential (openai-background)"]').exists()).toBe(true)
  })

  it('keeps background profile selection separate from its missing credential and targets only that realm', async () => {
    const intents: RecordedIntent[] = []
    const wrapper = mountProvidersPage({
      loadProviderStatus: async () => [...statuses, {
        providerId: 'openai-background', mode: 'openai_responses_background_text_v1',
        profileId: 'gocode-openai-responses-background-text/1', profileDigest: 'a'.repeat(64),
        readiness: 'not_selected', selected: false,
      }],
      requestCredentialIntent: async (provider, action, expectedRevision, rendererGeneration) => {
        intents.push({ provider, action, expectedRevision, rendererGeneration })
        return 'pending'
      },
    })
    await flushPromises()

    const row = wrapper.get('[data-provider-id="openai-background"]')
    expect(row.text()).toContain('Not selected')
    expect(row.text()).toContain('Credential missing')
    await row.get('button[aria-label="Enroll credential (openai-background)"]').trigger('click')
    await flushPromises()

    expect(intents).toEqual([{
      provider: 'openai-background', action: 'pair', expectedRevision: 7, rendererGeneration: 42,
    }])
  })

  it('uses native OAuth import help for Codex and API-key help for other credentials', async () => {
    const wrapper = mountProvidersPage({
      loadProviderStatus: async () => [...statuses,
        {
          providerId: 'openai-codex', mode: 'responses_text_v1', profileId: 'codex',
          profileDigest: '7'.repeat(64), readiness: 'not_selected', selected: false,
        },
        {
          providerId: 'github-copilot', mode: 'responses_text_v1', profileId: 'copilot',
          profileDigest: '8'.repeat(64), readiness: 'not_selected', selected: false,
        },
      ],
    })
    await flushPromises()

    expect(wrapper.find('button[aria-label="Import OAuth token (openai-codex)"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Manual native OAuth import')
    expect(wrapper.text()).toContain('Native API credential enrollment')
    expect(wrapper.find('[data-provider-id="github-copilot"]').text()).toContain('Manual native OAuth import')
    expect(wrapper.find('[data-provider-id="github-copilot"]').text()).not.toContain('Native API credential enrollment')
    expect(wrapper.text()).not.toContain('automatic OAuth')
  })

  it('renders quota source and availability attributes without raw timestamps', async () => {
    const wrapper = mountProvidersPage({
      loadProviderQuota: async () => [{
        providerId: 'openai', source: 'provider_reported', unit: 'credits',
        used: 100, limit: 100, remaining: 0, resetAt: null, observedAt: 12,
        availability: 'exhausted', windows: [{
          kind: 'FiveHourTime', used: 100, limit: 100, remaining: 0, resetAt: 20,
        }],
      }],
    })
    await flushPromises()

    const quota = wrapper.get('[data-provider-id="openai"] [data-quota="true"]')
    expect(quota.attributes('data-quota-source')).toBe('provider_reported')
    expect(quota.attributes('data-quota-availability')).toBe('exhausted')
    expect(quota.text()).toContain('aggregate reset is unknown')
    expect(quota.text()).not.toContain('1700000000')
    expect(quota.text()).toContain('Five-hour window')
  })

  it('uses credential readiness evidence instead of status readiness', async () => {
    const wrapper = mountProvidersPage({
      loadProviderStatus: async () => [{ ...statuses[0]!, providerId: 'openai', selected: true, readiness: 'ready' }],
      loadProviderCredentialEnrollmentStatus: async provider => ({
        ...credentialProjection(provider), readiness: 'missing', credentialState: 'missing',
      }),
    })
    await flushPromises()

    expect(wrapper.get('[data-provider-id="openai"] [data-readiness="true"]').text())
      .toContain('Credential missing (Native credential evidence)')
  })

  it('requests a pairing intent with the acquired generation and reloads statuses', async () => {
    const loadProviderStatus = vi.fn(async () => statuses)
    const intents: RecordedIntent[] = []
    const wrapper = mountProvidersPage({
      loadProviderStatus,
      requestCredentialIntent: async (provider, action, expectedRevision, rendererGeneration) => {
        intents.push({ provider, action, expectedRevision, rendererGeneration })
        return 'completed'
      },
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (deepseek)"]').trigger('click')
    await flushPromises()

    expect(intents).toEqual([{ provider: 'deepseek', action: 'pair', expectedRevision: 7, rendererGeneration: 42 }])
    expect(loadProviderStatus).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('Credential saved')
  })

  it('treats the completed disposition as success without a failure note', async () => {
    const wrapper = mountProvidersPage({ requestCredentialIntent: async () => 'completed' })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (openai)"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="status"]').text()).toBe('Credential saved')
    expect(wrapper.text()).not.toContain('Enrollment failed')
  })

  it('treats the pending disposition as in flight without a success reload', async () => {
    const loadProviderStatus = vi.fn(async () => statuses)
    const wrapper = mountProvidersPage({
      loadProviderStatus,
      requestCredentialIntent: async () => 'pending',
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (deepseek)"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="status"]').text()).toBe('Enrollment in progress')
    expect(loadProviderStatus).toHaveBeenCalledTimes(1)
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
        throw { code: 'provider_credential_intent_rejected' }
      },
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (openai)"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="status"]').text()).toBe('Enrollment failed: provider_credential_intent_rejected')
    expect(wrapper.get('[role="status"]').text()).not.toContain('[object Object]')
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
        return 'completed'
      },
    })
    await flushPromises()

    await wrapper.get('button[aria-label="Enroll credential (deepseek)"]').trigger('click')
    await flushPromises()

    expect(intents).toEqual([{ provider: 'deepseek', action: 'pair', expectedRevision: 7, rendererGeneration: 42 }])
    expect(wrapper.text()).toContain('Credential saved')
  })
})
