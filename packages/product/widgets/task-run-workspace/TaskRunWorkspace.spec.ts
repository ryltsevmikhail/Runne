import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TaskRunWorkspace from './TaskRunWorkspace.vue'

describe('TaskRun workspace', () => {
  it('renders durable timeline and keeps authority actions unavailable', () => {
    const wrapper = mount(TaskRunWorkspace, {
      props: {
        state: 'succeeded',
        entries: [{ eventId: '018f2e3a-7000-7000-8000-000000000212', sequence: 1, committedAt: 1, kind: 'completed', attemptId: null }],
        activeAttemptId: null,
        terminal: 'success',
        recovery: 'live',
      },
    })

    expect(wrapper.get('[aria-label="Task run timeline"]').text()).toContain('completed')
    expect(wrapper.text()).toContain('Terminal result: success')
    expect(wrapper.text()).not.toContain('next authority slice')
  })

  it('rejects unknown state and timeline kinds at the component boundary', () => {
    const wrapper = mount(TaskRunWorkspace, {
      props: { state: 'unknown', entries: [{ eventId: 'id', sequence: 1, committedAt: 1, kind: 'unknown', attemptId: null }], activeAttemptId: null, terminal: null, recovery: 'live' } as never,
    })
    expect(wrapper.get('[role="alert"]').text()).toContain('unavailable')
  })

  it('rejects unknown recovery and terminal values without rendering them', () => {
    for (const props of [
      { state: 'running', entries: [], activeAttemptId: null, terminal: null, recovery: 'unknown' },
      { state: 'running', entries: [], activeAttemptId: null, terminal: 'unknown', recovery: 'live' },
    ]) {
      const wrapper = mount(TaskRunWorkspace, { props: props as never })
      expect(wrapper.get('[role="alert"]').text()).toContain('unavailable')
      expect(wrapper.text()).not.toContain('unknown')
    }
  })
})
