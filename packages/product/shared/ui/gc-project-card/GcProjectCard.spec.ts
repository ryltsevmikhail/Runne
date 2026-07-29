import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcProjectCard from './GcProjectCard.vue'

const baseProject = {
  name: 'my-project',
  path: '/home/user/projects/my-project',
  slug: 'my-project-slug',
  status: 'ready' as const,
  modifiedAt: '2026-07-26 14:30',
}

describe('GcProjectCard', () => {
  it('renders project name, path, modifiedAt', () => {
    const wrapper = mount(GcProjectCard, {
      props: { project: baseProject },
    })

    expect(wrapper.text()).toContain('my-project')
    expect(wrapper.text()).toContain('/home/user/projects/my-project')
    expect(wrapper.text()).toContain('2026-07-26 14:30')
  })

  it('renders ready status text and class', () => {
    const wrapper = mount(GcProjectCard, {
      props: { project: { ...baseProject, status: 'ready' } },
    })

    expect(wrapper.text()).toContain('Ready')
    expect(wrapper.find('.gc-project-card-status--ready').exists()).toBe(true)
    expect(wrapper.find('.gc-project-card--ready').exists()).toBe(true)
  })

  it('renders stale status with attention text and orange border', () => {
    const wrapper = mount(GcProjectCard, {
      props: { project: { ...baseProject, status: 'stale' } },
    })

    expect(wrapper.text()).toContain('Attention')
    expect(wrapper.find('.gc-project-card-status--stale').exists()).toBe(true)
    expect(wrapper.find('.gc-project-card--stale').exists()).toBe(true)
  })

  it('renders recovery status with red border', () => {
    const wrapper = mount(GcProjectCard, {
      props: { project: { ...baseProject, status: 'recovery' } },
    })

    expect(wrapper.text()).toContain('Recovery')
    expect(wrapper.find('.gc-project-card-status--recovery').exists()).toBe(true)
    expect(wrapper.find('.gc-project-card--recovery').exists()).toBe(true)
  })

  it('emits click event on click', async () => {
    const wrapper = mount(GcProjectCard, {
      props: { project: baseProject },
    })

    await wrapper.trigger('click')
    expect(wrapper.emitted('click')).toBeTruthy()
    expect(wrapper.emitted('click')).toHaveLength(1)
  })

  it('renders actions slot', () => {
    const wrapper = mount(GcProjectCard, {
      props: { project: baseProject },
      slots: {
        actions: '<button>Edit</button>',
      },
    })

    expect(wrapper.find('.gc-project-card-actions').exists()).toBe(true)
    expect(wrapper.find('.gc-project-card-actions').text()).toBe('Edit')
  })
})
