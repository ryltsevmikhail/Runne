import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { TaskRunEffects } from '@/entities/task-run'
import TaskRunEffectsPanel from './TaskRunEffectsPanel.vue'

const base: TaskRunEffects = {
  taskRunId: '018f47a2-7a12-7abc-8abc-123456789abc',
  streamVersion: 9,
  attemptId: null,
  cancellationRequested: true,
  localCommand: null,
  remote: {
    outcome: 'unknown',
    publication: 'unknown',
    accounting: 'unknown',
    cancellation: 'requested',
    availability: 'unavailable',
    capabilities: { statusCheck: true, streamResume: false, remoteCancel: true },
    usageKnown: null,
  },
  successor: 'requires_duplicate_effect_acknowledgment',
}

describe('TaskRunEffectsPanel', () => {
  it('shows the duplicate-work and cost warning from successor eligibility', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: base, pending: false, unavailable: false, stale: false } })
    expect(wrapper.text()).toContain('The previous run may still be executing')
    expect(wrapper.text()).toContain('A new attempt can duplicate work and charges')
    expect(wrapper.text()).toContain('Explicit successor: requires duplicate-effect acknowledgment')
  })

  it('keeps an actual remote completion visible after a cancellation request', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: { ...base, remote: { ...base.remote, outcome: 'completed' } }, pending: false, unavailable: false, stale: false } })
    expect(wrapper.text()).toContain('Remote outcome: completed')
    expect(wrapper.text()).toContain('Remote cancellation: requested')
    expect(wrapper.text()).not.toContain('Remote outcome: cancelled')
  })

  it('keeps completed status, provider usage, and financial settlement separate', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: {
      ...base,
      cancellationRequested: false,
      remote: { ...base.remote, outcome: 'completed', cancellation: 'not_requested', usageKnown: true },
      successor: 'blocked',
    }, pending: false, unavailable: false, stale: false } })
    expect(wrapper.text()).toContain('Remote outcome: completed')
    expect(wrapper.text()).toContain('Usage known: yes')
    expect(wrapper.text()).toContain('financial settlement could not be confirmed')
    expect(wrapper.text()).not.toContain('Remote outcome: failed')
    expect(wrapper.text()).not.toContain('Remote cancellation: confirmed')
  })

  it('shows a factual remote completion when local publication was withheld', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: {
      ...base,
      cancellationRequested: true,
      remote: { ...base.remote, outcome: 'completed', publication: 'withheld', usageKnown: true },
    }, pending: false, unavailable: false, stale: false } })
    expect(wrapper.text()).toContain('Remote outcome: completed')
    expect(wrapper.text()).toContain('Response text: withheld from local publication')
    expect(wrapper.text()).not.toContain('Remote outcome: failed')
    expect(wrapper.text()).not.toContain('Response text: available for local publication')
  })

  it('shows local stop proof and remote uncertainty as separate facts', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: { ...base, localCommand: { outcome: 'outcome_unknown', stop: 'confirmed', exitCode: null } }, pending: false, unavailable: false, stale: false } })
    expect(wrapper.text()).toContain('Command outcome: outcome unknown')
    expect(wrapper.text()).toContain('Process stop: confirmed')
    expect(wrapper.text()).toContain('Remote outcome: unknown')
  })

  it('shows fresh remote running and unconfirmed cancellation distinctly from unknown', () => {
    const running = mount(TaskRunEffectsPanel, { props: { effects: {
      ...base,
      remote: {
        ...base.remote,
        outcome: 'running',
        publication: 'unknown',
        accounting: 'unknown',
        cancellation: 'unconfirmed',
        usageKnown: null,
      },
    }, pending: false, unavailable: false, stale: false } })
    expect(running.text()).toContain('Remote outcome: running')
    expect(running.text()).toContain('Remote cancellation: unconfirmed')
    expect(running.text()).not.toContain('Remote outcome: unknown')
    expect(running.text()).not.toContain('Remote cancellation: confirmed')

    const unknown = mount(TaskRunEffectsPanel, { props: { effects: base, pending: false, unavailable: false, stale: false } })
    expect(unknown.text()).toContain('Remote outcome: unknown')
    expect(unknown.text()).toContain('Remote cancellation: requested')
  })

  it('shows a nonzero local exit as failure even when the workflow snapshot succeeded', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: { ...base, localCommand: { outcome: 'exited', stop: 'confirmed', exitCode: 7 } }, pending: false, unavailable: false, stale: false } })
    expect(wrapper.text()).toContain('Command outcome: exited with failure')
    expect(wrapper.text()).toContain('Process exit code: 7')
  })

  it('renders stop-unconfirmed and version-mismatch states without success claims', () => {
    const unconfirmed = mount(TaskRunEffectsPanel, { props: { effects: { ...base, localCommand: { outcome: 'outcome_unknown', stop: 'unconfirmed', exitCode: null } }, pending: false, unavailable: false, stale: false } })
    expect(unconfirmed.text()).toContain('Process stop: unconfirmed')
    expect(unconfirmed.text()).not.toContain('cancelled')
    const stale = mount(TaskRunEffectsPanel, { props: { effects: null, pending: false, unavailable: false, stale: true } })
    expect(stale.text()).toContain('Execution effects are being refreshed')
  })

  it('does not invent facts when the query is unavailable', () => {
    const wrapper = mount(TaskRunEffectsPanel, { props: { effects: null, pending: false, unavailable: true, stale: false } })
    expect(wrapper.text()).toContain('No process or remote outcome is inferred')
    expect(wrapper.text()).not.toContain('Remote outcome:')
  })
})

it('labels an already completed effect without claiming confirmed cancellation', () => {
  const wrapper = mount(TaskRunEffectsPanel, { props: { effects: {
    ...base, remote: { ...base.remote, outcome: 'completed', cancellation: 'already_terminal' },
  }, pending: false, unavailable: false, stale: false } })
  expect(wrapper.text()).toContain('Remote cancellation: provider request finished')
  expect(wrapper.text()).toContain('Remote outcome: completed')
  expect(wrapper.text()).not.toContain('Remote cancellation: confirmed')
})
