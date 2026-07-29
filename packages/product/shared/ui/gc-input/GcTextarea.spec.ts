import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcTextarea from './GcTextarea.vue'

describe('GcTextarea', () => {
  it('renders with modelValue', () => {
    const wrapper = mount(GcTextarea, { props: { modelValue: 'content' } })
    expect(wrapper.find('textarea').element.value).toBe('content')
  })

  it('emits update:modelValue on input', async () => {
    const wrapper = mount(GcTextarea, { props: { modelValue: '' } })
    await wrapper.find('textarea').setValue('new')
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual(['new'])
  })

  it('shows label and helper', () => {
    const wrapper = mount(GcTextarea, { props: { modelValue: '', label: 'Bio', helper: 'Max 200 chars' } })
    expect(wrapper.text()).toContain('Bio')
    expect(wrapper.text()).toContain('Max 200 chars')
    expect(wrapper.find('label').attributes('for')).toBe(wrapper.find('textarea').attributes('id'))
  })

  it('disables when state is disabled', () => {
    const wrapper = mount(GcTextarea, { props: { modelValue: '', state: 'disabled' } })
    expect(wrapper.find('textarea').attributes('disabled')).toBeDefined()
  })

  it('renders error state', () => {
    const wrapper = mount(GcTextarea, { props: { modelValue: '', state: 'error', helper: 'Required' } })
    expect(wrapper.find('.gc-input-wrapper').attributes('class')).toContain('error')
    expect(wrapper.find('textarea').attributes('aria-invalid')).toBe('true')
  })

  it('supports custom rows', () => {
    const wrapper = mount(GcTextarea, { props: { modelValue: '', rows: 6 } })
    expect(wrapper.find('textarea').attributes('rows')).toBe('6')
  })
})
