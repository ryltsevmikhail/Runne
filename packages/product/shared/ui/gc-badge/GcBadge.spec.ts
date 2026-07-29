import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcBadge from './GcBadge.vue'

describe('GcBadge', () => {
  it('renders ready badge', () => {
    const wrapper = mount(GcBadge, {
      props: { status: 'ready' },
      slots: { default: 'Ready' },
    })
    expect(wrapper.attributes('class')).toContain('gc-badge--ready')
    expect(wrapper.text()).toBe('Ready')
    expect(wrapper.find('.gc-badge-dot').exists()).toBe(false)
  })

  it('renders error badge', () => {
    const wrapper = mount(GcBadge, {
      props: { status: 'error' },
      slots: { default: 'Error' },
    })
    expect(wrapper.attributes('class')).toContain('gc-badge--error')
    expect(wrapper.text()).toBe('Error')
  })

  it('renders running badge with pulse dot', () => {
    const wrapper = mount(GcBadge, {
      props: { status: 'running' },
      slots: { default: 'Running' },
    })
    expect(wrapper.attributes('class')).toContain('gc-badge--running')
    expect(wrapper.find('.gc-badge-dot').exists()).toBe(true)
    expect(wrapper.text()).toContain('Running')
  })

  it('renders offline badge', () => {
    const wrapper = mount(GcBadge, {
      props: { status: 'offline' },
      slots: { default: 'Offline' },
    })
    expect(wrapper.attributes('class')).toContain('gc-badge--offline')
    expect(wrapper.text()).toBe('Offline')
  })

  it('renders review badge', () => {
    const wrapper = mount(GcBadge, {
      props: { status: 'review' },
      slots: { default: 'Review' },
    })
    expect(wrapper.attributes('class')).toContain('gc-badge--review')
    expect(wrapper.text()).toBe('Review')
  })

  it('renders streaming badge with pulse dot', () => {
    const wrapper = mount(GcBadge, {
      props: { status: 'streaming' },
      slots: { default: 'Streaming' },
    })
    expect(wrapper.attributes('class')).toContain('gc-badge--streaming')
    expect(wrapper.find('.gc-badge-dot').exists()).toBe(true)
    expect(wrapper.text()).toContain('Streaming')
  })
})
