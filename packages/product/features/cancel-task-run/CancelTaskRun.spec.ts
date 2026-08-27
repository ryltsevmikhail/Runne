import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import CancelTaskRun from './CancelTaskRun.vue'

describe('CancelTaskRun', () => {
  it('requests cancellation only while dispatch is admitted', async () => {
    const wrapper = mount(CancelTaskRun, { props: { disabled: false, pending: false } })
    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('request')).toEqual([[]])

    await wrapper.setProps({ disabled: true })
    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('request')).toEqual([[]])
  })
})
