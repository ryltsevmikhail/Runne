import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcRecoveryState from './GcRecoveryState.vue'

describe('GcRecoveryState', () => {
  it('restored: shows green checkmark and restored text', () => {
    const wrapper = mount(GcRecoveryState, {
      props: { state: 'restored' },
    })
    expect(wrapper.text()).toContain('Session restored')
    expect(wrapper.text()).toContain('Your workspace has been recovered.')
  })

  it('conflict: shows buttons Keep local and Use remote', () => {
    const wrapper = mount(GcRecoveryState, {
      props: { state: 'conflict' },
    })
    expect(wrapper.text()).toContain('Session conflict')
    const localBtn = wrapper.find('.gc-recovery-btn--local')
    const remoteBtn = wrapper.find('.gc-recovery-btn--remote')
    expect(localBtn.exists()).toBe(true)
    expect(localBtn.text()).toBe('Keep local')
    expect(remoteBtn.exists()).toBe(true)
    expect(remoteBtn.text()).toBe('Use remote')
  })

  it('conflict: emits resolve with correct action', async () => {
    const wrapper = mount(GcRecoveryState, {
      props: { state: 'conflict' },
    })
    await wrapper.find('.gc-recovery-btn--local').trigger('click')
    expect(wrapper.emitted('resolve')).toBeTruthy()
    expect(wrapper.emitted('resolve')![0]).toEqual(['local'])

    await wrapper.find('.gc-recovery-btn--remote').trigger('click')
    expect(wrapper.emitted('resolve')![1]).toEqual(['remote'])
  })

  it('corrupt: shows Start fresh button', () => {
    const wrapper = mount(GcRecoveryState, {
      props: { state: 'corrupt' },
    })
    expect(wrapper.text()).toContain('Session corrupt')
    const freshBtn = wrapper.find('.gc-recovery-btn--fresh')
    expect(freshBtn.exists()).toBe(true)
    expect(freshBtn.text()).toBe('Start fresh')
  })

  it('corrupt: emits reset', async () => {
    const wrapper = mount(GcRecoveryState, {
      props: { state: 'corrupt' },
    })
    await wrapper.find('.gc-recovery-btn--fresh').trigger('click')
    expect(wrapper.emitted('reset')).toBeTruthy()
  })
})
