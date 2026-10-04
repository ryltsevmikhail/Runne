import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import TaskRunSuccessorAction from './TaskRunSuccessorAction.vue'

const mocked = vi.hoisted(() => ({ supersede: vi.fn() }))
vi.mock('@/entities/task-run', () => ({ supersedeUnknownTaskRun: mocked.supersede }))

const predecessor = '018f2e3a-7000-7000-8000-000000000210'
const successor = '018f2e3a-7000-7000-8000-000000000211'

function render(runtimeLive = true) {
  const created = vi.fn()
  const wrapper = mount(TaskRunSuccessorAction, {
    props: { taskRunId: predecessor, expectedVersion: 5, eligibility: 'requires_duplicate_effect_acknowledgment', runtimeLive, onCreated: created },
    global: { stubs: { GcAlert: true, GcButton: { template: '<button :disabled="$attrs.disabled"><slot /></button>' } } },
  })
  return { wrapper, created }
}

describe('TaskRun successor acknowledgment races', () => {
  it('clears the acknowledgment when the predecessor version changes', async () => {
    mocked.supersede.mockReset()
    const { wrapper } = render()
    await wrapper.find('input').setValue(true)
    expect((wrapper.find('input').element as HTMLInputElement).checked).toBe(true)
    await wrapper.setProps({ expectedVersion: 6 })
    expect((wrapper.find('input').element as HTMLInputElement).checked).toBe(false)
    wrapper.unmount()
  })

  it('ignores a held acknowledgment after runtime loss', async () => {
    mocked.supersede.mockReset()
    let finish!: (value: unknown) => void
    mocked.supersede.mockReturnValue(new Promise(resolve => { finish = resolve }))
    const { wrapper, created } = render()
    await wrapper.find('input').setValue(true)
    await wrapper.find('button').trigger('click')
    await wrapper.setProps({ runtimeLive: false })
    finish({ predecessorTaskRunId: predecessor, predecessorVersion: 6, taskRunId: successor, streamVersion: 2 })
    await flushPromises()
    expect(created).not.toHaveBeenCalled()
    expect(mocked.supersede).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('invalidates a held acknowledgment when the route changes TaskRuns', async () => {
    mocked.supersede.mockReset()
    let finish!: (value: unknown) => void
    mocked.supersede.mockReturnValue(new Promise(resolve => { finish = resolve }))
    const { wrapper, created } = render()
    await wrapper.find('input').setValue(true)
    await wrapper.find('button').trigger('click')
    const nextTask = '018f2e3a-7000-7000-8000-000000000212'
    await wrapper.setProps({ taskRunId: nextTask, expectedVersion: 4 })
    expect((wrapper.find('input').element as HTMLInputElement).checked).toBe(false)
    finish({ predecessorTaskRunId: predecessor, predecessorVersion: 6, taskRunId: successor, streamVersion: 2 })
    await flushPromises()
    expect(created).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
