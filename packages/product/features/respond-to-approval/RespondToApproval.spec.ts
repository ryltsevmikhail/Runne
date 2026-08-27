import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import RespondToApproval from './RespondToApproval.vue'

describe('RespondToApproval', () => {
  it('emits only an explicit decision while enabled', async () => {
    const wrapper = mount(RespondToApproval, { props: { disabled: false, pending: false } })
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    await wrapper.get('[data-approval-action="deny"]').trigger('click')
    expect(wrapper.emitted('decide')).toEqual([['approve'], ['deny']])
  })

  it('fails closed while an authority refresh is pending', async () => {
    const wrapper = mount(RespondToApproval, { props: { disabled: false, pending: true } })
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    expect(wrapper.emitted('decide')).toBeUndefined()
  })
})
