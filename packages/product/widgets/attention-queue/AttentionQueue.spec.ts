import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import AttentionQueue from './AttentionQueue.vue'

const item = {
  approvalId: '018f2e3a-7000-7000-8000-000000000212',
  action: 'fs:write',
  resource: 'workspace:/src/main.rs',
  riskSummary: 'write source',
  state: 'pending' as const,
}

describe('AttentionQueue', () => {
  it('renders safe approval details and relays an explicit decision', async () => {
    const wrapper = mount(AttentionQueue, { props: { items: [item], disabled: false, pendingId: null } })
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    expect(wrapper.text()).toContain('workspace:/src/main.rs')
    expect(wrapper.emitted('decide')).toEqual([[item.approvalId, 'approve']])
  })

  it('does not offer an action for a non-pending item', () => {
    const wrapper = mount(AttentionQueue, { props: { items: [{ ...item, state: 'expired' }], disabled: false, pendingId: null } })
    expect(wrapper.find('[data-approval-action]').exists()).toBe(false)
  })
})
