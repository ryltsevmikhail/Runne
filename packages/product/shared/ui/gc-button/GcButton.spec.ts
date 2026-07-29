import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcButton from './GcButton.vue'

describe('GcButton', () => {
  it('renders primary variant by default', () => {
    const wrapper = mount(GcButton, { slots: { default: 'Click me' } })
    expect(wrapper.text()).toBe('Click me')
    expect(wrapper.attributes('class')).toContain('gc-button--primary')
  })

  it('renders ghost variant', () => {
    const wrapper = mount(GcButton, { props: { variant: 'ghost' } })
    expect(wrapper.attributes('class')).toContain('gc-button--ghost')
  })

  it('renders secondary variant', () => {
    const wrapper = mount(GcButton, { props: { variant: 'secondary' } })
    expect(wrapper.attributes('class')).toContain('gc-button--secondary')
  })

  it('renders delete variant with error color', () => {
    const wrapper = mount(GcButton, { props: { variant: 'delete' } })
    expect(wrapper.attributes('class')).toContain('gc-button--delete')
  })

  it('disables button when variant is disabled', () => {
    const wrapper = mount(GcButton, { props: { variant: 'disabled' } })
    expect(wrapper.attributes('disabled')).toBeDefined()
  })

  it('disables button when disabled prop is true', () => {
    const wrapper = mount(GcButton, { props: { disabled: true } })
    expect(wrapper.attributes('disabled')).toBeDefined()
  })

  it('emits click event', async () => {
    const wrapper = mount(GcButton)
    await wrapper.trigger('click')
    expect(wrapper.emitted('click')).toBeTruthy()
  })

  it('renders sm size', () => {
    const wrapper = mount(GcButton, { props: { size: 'sm' } })
    expect(wrapper.attributes('class')).toContain('gc-button--sm')
  })

  it('renders md size by default', () => {
    const wrapper = mount(GcButton)
    expect(wrapper.attributes('class')).toContain('gc-button--md')
  })
})
