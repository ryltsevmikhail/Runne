import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import ApprovalsPage from './ApprovalsPage.vue'

const id = '018f2e3a-7000-7000-8000-000000000212'
const approval = { approvalId: id, taskRunId: id, attemptId: null, invocationId: id, action: 'fs:write', resource: 'workspace:/src/main.rs', actionDigest: '1'.repeat(64), policyRevision: 7, requestVersion: 3, expiresAt: 2_000, riskSummary: 'write source', state: 'pending' as const }

describe('ApprovalsPage', () => {
  it('renders the runtime-owned attention queue', async () => {
    const wrapper = mount(ApprovalsPage, { props: { load: async () => [approval] } })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(wrapper.text()).toContain('fs:write')
    expect(wrapper.text()).toContain('workspace:/src/main.rs')
  })

  it('offers version-bound approve and deny actions and removes the acknowledged item', async () => {
    const decide = async () => ({ approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' as const })
    const wrapper = mount(ApprovalsPage, {
      props: { load: async () => [approval], acquireGeneration: async () => 8, decide },
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    expect(wrapper.text()).toContain('No pending approvals.')
  })
})
