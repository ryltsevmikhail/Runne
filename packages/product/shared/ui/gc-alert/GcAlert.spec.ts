import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcAlert from './GcAlert.vue'

describe('GcAlert', () => {
  it('renders title', () => {
    const wrapper = mount(GcAlert, {
      props: { level: 'info', title: 'Test Title' },
    })
    expect(wrapper.text()).toContain('Test Title')
  })

  it('renders slot content as description', () => {
    const wrapper = mount(GcAlert, {
      props: { level: 'info', title: 'Title' },
      slots: { default: 'Description text' },
    })
    expect(wrapper.text()).toContain('Description text')
  })

  it('emits dismiss when dismiss button clicked', async () => {
    const wrapper = mount(GcAlert, {
      props: { level: 'info', title: 'Title', dismissible: true },
    })
    await wrapper.find('.gc-alert-dismiss').trigger('click')
    expect(wrapper.emitted('dismiss')).toBeTruthy()
  })

  it('renders all four levels', () => {
    const levels: Array<'success' | 'info' | 'warning' | 'error'> = [
      'success', 'info', 'warning', 'error',
    ]
    for (const level of levels) {
      const wrapper = mount(GcAlert, {
        props: { level, title: level },
      })
      expect(wrapper.attributes('class')).toContain(`gc-alert--${level}`)
    }
  })

  it('shows dismiss button when dismissible is true', () => {
    const wrapper = mount(GcAlert, {
      props: { level: 'info', title: 'Title', dismissible: true },
    })
    expect(wrapper.find('.gc-alert-dismiss').exists()).toBe(true)
  })

  it('hides dismiss button when dismissible is false', () => {
    const wrapper = mount(GcAlert, {
      props: { level: 'info', title: 'Title', dismissible: false },
    })
    expect(wrapper.find('.gc-alert-dismiss').exists()).toBe(false)
  })
})
