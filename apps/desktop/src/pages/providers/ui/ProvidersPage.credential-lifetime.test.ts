import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import {
  getProviderCredentialEnrollmentStatus,
  projectProviderCredentialSnapshot,
} from '@/shared/api/platform/providers'

import ProvidersPage from './ProvidersPage.vue'

const rendererClosureCanary = 'D1_1C_RENDERER_CLOSED_CANARY'

const status = {
  providerId: 'openai',
  mode: 'openai_responses_text_v1',
  profileId: 'openai-responses-text-v1',
  profileDigest: '1'.repeat(64),
  readiness: 'ready',
  selected: true,
} as const

const closedProjection = {
  providerId: 'openai',
  credentialState: 'configured',
  readiness: 'ready',
  lifecycleRevision: 7,
  readinessRevision: 8,
  observedAt: 9,
  verificationState: 'local_verified',
  verificationRevision: 7,
  pendingOperation: null,
  cleanupPending: false,
  lastDisposition: 'completed',
  credential: rendererClosureCanary,
} as const

describe('ProvidersPage credential lifetime', () => {
  it('rejects a credential-shaped projection without rendering material controls or values', async () => {
    expect(() => projectProviderCredentialSnapshot(closedProjection)).toThrow(
      'Invalid provider credential projection',
    )

    const wrapper = mount(ProvidersPage, {
      props: {
        loadProviderStatus: async () => [status],
        loadProviderCredentialEnrollmentStatus: provider => getProviderCredentialEnrollmentStatus(
          provider,
          async () => closedProjection,
        ),
      },
    })
    await flushPromises()

    expect(wrapper.findAll('input, textarea')).toHaveLength(0)
    expect(wrapper.html()).not.toContain(rendererClosureCanary)
    expect(wrapper.text()).not.toContain(rendererClosureCanary)
  })
})
