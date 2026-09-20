import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { TaskRunRecovery } from '@/entities/task-run'
import { currentLocale } from '@/shared/i18n'

import TaskRunRecoveryPanel from './TaskRunRecoveryPanel.vue'

const recoveries: readonly TaskRunRecovery[] = ['live', 'reconnecting', 'incompatible', 'revoked', 'resync_required', 'fatal']

function mountPanel(recovery: TaskRunRecovery, lastCommittedAt: number | null = 42) {
  return mount(TaskRunRecoveryPanel, { props: { recovery, projectionRevision: 3, streamVersion: 4, lastCommittedAt } })
}

describe('TaskRunRecoveryPanel', () => {
  it('renders a distinct loss-of-connection warning for reconnecting', () => {
    const wrapper = mountPanel('reconnecting')
    expect(wrapper.text()).toContain('Connection to the task stream was lost.')
    expect(wrapper.find('.gc-alert--warning').exists()).toBe(true)
    expect(wrapper.find('.gc-alert--error').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('renders a distinct revalidation warning for resync_required', () => {
    const wrapper = mountPanel('resync_required')
    expect(wrapper.text()).toContain('Replay recovery needs revalidation.')
    expect(wrapper.find('.gc-alert--warning').exists()).toBe(true)
    expect(wrapper.find('.gc-alert--error').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('renders a distinct permanent-failure alert for fatal', () => {
    const wrapper = mountPanel('fatal')
    expect(wrapper.text()).toContain('Replay recovery failed permanently.')
    expect(wrapper.find('.gc-alert--error').exists()).toBe(true)
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })

  it('renders a distinct access-revoked alert for revoked', () => {
    const wrapper = mountPanel('revoked')
    expect(wrapper.text()).toContain('Access to this task run was revoked.')
    expect(wrapper.find('.gc-alert--error').exists()).toBe(true)
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })

  it('renders a distinct runtime-incompatibility alert for incompatible', () => {
    const wrapper = mountPanel('incompatible')
    expect(wrapper.text()).toContain('Runtime is incompatible with this task run.')
    expect(wrapper.find('.gc-alert--error').exists()).toBe(true)
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })

  it('exposes stale confirmed-snapshot metadata without a raw timestamp', () => {
    const wrapper = mountPanel('resync_required')
    const stale = wrapper.get('[role="status"]')
    expect(stale.text()).toContain('revision 3')
    expect(stale.text()).toContain('stream 4')
    expect(stale.text()).not.toContain('event at')
    expect(stale.text()).toContain('data may be outdated')
    expect(wrapper.text()).not.toContain('42')
  })

  it('reports the absence of confirmed events without a fake timestamp', () => {
    const wrapper = mountPanel('fatal', null)
    expect(wrapper.get('[role="status"]').text()).toContain('revision 3')
    expect(wrapper.get('[role="status"]').text()).toContain('no confirmed events')
    expect(wrapper.text()).not.toContain('event at')
  })

  it('renders recovery texts through the active locale', () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mountPanel('reconnecting')
      expect(wrapper.text()).toContain('Соединение с потоком задач потеряно.')
      expect(wrapper.get('[role="status"]').text()).toContain('поток 4')
    } finally {
      currentLocale.value = previousLocale
    }
  })

  it('renders nothing in the live state', () => {
    const wrapper = mountPanel('live')
    expect(wrapper.text()).toBe('')
    expect(wrapper.find('.gc-alert').exists()).toBe(false)
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('never renders an action button for any recovery state', () => {
    for (const recovery of recoveries) {
      const wrapper = mountPanel(recovery)
      expect(wrapper.find('button').exists()).toBe(false)
      wrapper.unmount()
    }
  })

  it('keeps the non-live recovery texts pairwise distinct', () => {
    const texts = recoveries.filter(recovery => recovery !== 'live').map(recovery => mountPanel(recovery).text())
    expect(new Set(texts).size).toBe(texts.length)
  })
})
