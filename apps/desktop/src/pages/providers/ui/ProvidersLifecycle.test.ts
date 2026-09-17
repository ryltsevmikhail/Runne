import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import type { ProviderCredentialIntentDisposition, ProviderCredentialProjection } from '@/shared/api/platform/providers'

import ProvidersPage from './ProvidersPage.vue'

function configured(overrides: Partial<ProviderCredentialProjection> = {}): ProviderCredentialProjection {
  return {
    providerId: 'deepseek', credentialState: 'configured', readiness: 'ready',
    lifecycleRevision: 7, readinessRevision: 2, observedAt: 9,
    verificationState: 'local_verified', verificationRevision: 1,
    pendingOperation: null, cleanupPending: false, lastDisposition: 'completed',
    ...overrides,
  }
}

function render(
  load: () => Promise<ProviderCredentialProjection> = async () => configured(),
  request = vi.fn(async (): Promise<ProviderCredentialIntentDisposition> => 'completed'),
) {
  return {
    request,
    wrapper: mount(ProvidersPage, { props: {
      loadProviderStatus: async () => [{
        providerId: 'deepseek', selected: true, readiness: 'ready',
        mode: 'deepseek_responses_text_v1', profileId: 'deepseek-responses-text-v1', profileDigest: '1'.repeat(64),
      }],
      loadProviderCredentialEnrollmentStatus: async provider => {
        if (provider !== 'deepseek') throw new Error('not configured')
        return load()
      },
      acquireGeneration: async () => 42,
      requestCredentialIntent: request,
    } }),
  }
}

describe('provider credential lifecycle', () => {
  it('uses Pair for rotation with the admitted lifecycle revision and no webview secret field', async () => {
    const { wrapper, request } = render()
    await flushPromises()
    expect(wrapper.find('input, textarea').exists()).toBe(false)
    await wrapper.get('button[aria-label="Rotate credential (deepseek)"]').trigger('click')
    await flushPromises()
    expect(request).toHaveBeenCalledExactlyOnceWith('deepseek', 'pair', 7, 42)
  })

  it('refreshes the revision before native Revoke and reloads the authoritative result', async () => {
    let reads = 0
    const { wrapper, request } = render(async () => {
      reads += 1
      return configured({ lifecycleRevision: reads + 6, credentialState: reads >= 3 ? 'missing' : 'configured' })
    })
    await flushPromises()
    await wrapper.get('button[aria-label="Revoke credential (deepseek)"]').trigger('click')
    await flushPromises()
    expect(request).toHaveBeenCalledExactlyOnceWith('deepseek', 'revoke', 8, 42)
    expect(wrapper.text()).toContain('Credential revoked')
    expect(wrapper.find('button[aria-label="Revoke credential (deepseek)"]').exists()).toBe(false)
    expect(wrapper.find('button[aria-label="Enroll credential (deepseek)"]').exists()).toBe(true)
  })

  it('does not dispatch Revoke if fresh status no longer permits it', async () => {
    let reads = 0
    const { wrapper, request } = render(async () => configured({
      credentialState: ++reads > 1 ? 'missing' : 'configured',
    }))
    await flushPromises()
    await wrapper.get('button[aria-label="Revoke credential (deepseek)"]').trigger('click')
    await flushPromises()
    expect(request).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('provider_credential_state_changed')
  })

  it.each([
    { pendingOperation: 'revoking' as const },
    { cleanupPending: true },
  ])('disables conflicting actions while lifecycle work is pending: %j', async status => {
    const { wrapper, request } = render(async () => configured(status))
    await flushPromises()
    for (const button of wrapper.findAll('button')) {
      expect(button.attributes('disabled')).toBeDefined()
      await button.trigger('click')
    }
    expect(request).not.toHaveBeenCalled()
  })

  it('disables both actions while awaiting native confirmation and keeps state after cancellation', async () => {
    let finish: ((value: ProviderCredentialIntentDisposition) => void) | undefined
    const request = vi.fn(() => new Promise<ProviderCredentialIntentDisposition>(resolve => { finish = resolve }))
    const { wrapper } = render(undefined, request)
    await flushPromises()
    await wrapper.get('button[aria-label="Revoke credential (deepseek)"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('button').every(button => button.attributes('disabled') !== undefined)).toBe(true)
    finish?.('cancelled')
    await flushPromises()
    expect(wrapper.text()).not.toContain('Credential revoked')
    expect(wrapper.get('button[aria-label="Revoke credential (deepseek)"]').attributes('disabled')).toBeUndefined()
  })
})
