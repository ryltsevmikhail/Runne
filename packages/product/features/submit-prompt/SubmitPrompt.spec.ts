import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import SubmitPrompt from './SubmitPrompt.vue'

describe('SubmitPrompt', () => {
  it('emits one trimmed prompt only while live', async () => {
    const wrapper = mount(SubmitPrompt, { props: { disabled: false, pending: false } })
    await wrapper.get('textarea').setValue('  explain this  ')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')).toEqual([['explain this']])
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('')
  })

  it('fails closed while stale or pending', async () => {
    const wrapper = mount(SubmitPrompt, { props: { disabled: true, pending: false } })
    await wrapper.get('textarea').setValue('must not send')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()

    await wrapper.setProps({ disabled: false, pending: true })
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()
  })
})
