import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { RuntimeLifecycleStatus } from '@/shared/api/platform/bootstrap'
import RuntimeStatus from './RuntimeStatus.vue'

describe('runtime lifecycle status', () => {
  it.each([
    ['starting', 'Runtime starting'],
    ['ready', 'Runtime ready'],
    ['restarting', 'Runtime restarting'],
    ['degraded', 'Runtime degraded'],
    ['failed', 'Runtime failed'],
    ['external', 'External runtime'],
  ] satisfies Array<[RuntimeLifecycleStatus, string]>)(
    'renders the closed %s state',
    (lifecycle, label) => {
      const wrapper = mount(RuntimeStatus, {
        props: {
          mode: lifecycle === 'external' ? 'external_local' : 'bundled',
          connection: lifecycle === 'ready' ? 'live' : 'reconnecting',
          lifecycle,
          failure: null,
        },
      })

      expect(wrapper.get('[role="status"]').text()).toContain(label)
      expect(wrapper.get('[role="status"]').attributes('data-lifecycle')).toBe(lifecycle)
    },
  )

  it('renders only the actionable closed failure label', () => {
    const wrapper = mount(RuntimeStatus, {
      props: {
        mode: 'bundled',
        connection: 'fatal',
        lifecycle: 'failed',
        failure: 'downgraded_external_profile',
      },
    })

    expect(wrapper.text()).toContain('Unsafe transport was rejected')
    expect(wrapper.text()).not.toContain('token')
    expect(wrapper.text()).not.toContain('path')
  })
})
