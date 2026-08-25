import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TaskRunTimeline from './TaskRunTimeline.vue'

describe('TaskRunTimeline', () => {
  it('fails closed for an unknown timeline kind', () => {
    const wrapper = mount(TaskRunTimeline, {
      props: { entries: [{ eventId: 'id', sequence: 1, committedAt: 1, kind: 'unknown', attemptId: null }] as never },
    })
    expect(wrapper.get('[role="alert"]').text()).toContain('unavailable')
  })
})
