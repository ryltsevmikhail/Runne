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
})
