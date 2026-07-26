import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcInput from './GcInput.vue'

describe('GcInput', () => {
  it('renders with modelValue', () => {
    const wrapper = mount(GcInput, { props: { modelValue: 'hello' } })
    expect(wrapper.find('input').element.value).toBe('hello')
  })

  it('emits update:modelValue on input', async () => {
    const wrapper = mount(GcInput, { props: { modelValue: '' } })
    await wrapper.find('input').setValue('test')
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual(['test'])
  })

  it('shows label when provided', () => {
    const wrapper = mount(GcInput, { props: { modelValue: '', label: 'Email' } })
    expect(wrapper.text()).toContain('Email')
  })

  it('shows helper text', () => {
    const wrapper = mount(GcInput, { props: { modelValue: '', helper: 'Required' } })
    expect(wrapper.text()).toContain('Required')
  })

  it('renders error state with red border', () => {
    const wrapper = mount(GcInput, { props: { modelValue: '', state: 'error' } })
    expect(wrapper.find('.gc-input-wrapper').attributes('class')).toContain('error')
  })

  it('disables input when state is disabled', () => {
    const wrapper = mount(GcInput, { props: { modelValue: '', state: 'disabled' } })
    expect(wrapper.find('input').attributes('disabled')).toBeDefined()
  })

  it('renders leading and trailing slots', () => {
    const wrapper = mount(GcInput, {
      props: { modelValue: '' },
      slots: { leading: '<span class="icon-l">🔍</span>', trailing: '<span class="icon-r">✕</span>' },
    })
    expect(wrapper.find('.icon-l').exists()).toBe(true)
    expect(wrapper.find('.icon-r').exists()).toBe(true)
  })

  it('supports custom type', () => {
    const wrapper = mount(GcInput, { props: { modelValue: '', type: 'password' } })
    expect(wrapper.find('input').attributes('type')).toBe('password')
  })
})
