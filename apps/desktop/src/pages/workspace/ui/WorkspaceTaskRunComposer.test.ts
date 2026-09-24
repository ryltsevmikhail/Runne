import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it, vi } from 'vitest'
import WorkspaceTaskRunComposer from './WorkspaceTaskRunComposer.vue'

const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const conversationId = '018f2e3a-7000-7000-8000-000000000211'
const taskRunId = '018f2e3a-7000-7000-8000-000000000210'

async function mountComposer(overrides: Record<string, unknown> = {}) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: `/workspaces/${workspaceId}`, component: { template: '<div>Workspace</div>' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div>TaskRun</div>' } },
    ],
  })
  await router.push(`/workspaces/${workspaceId}`)
  await router.isReady()
  const wrapper = mount(WorkspaceTaskRunComposer, {
    props: {
      workspaceId,
      openConversation: vi.fn(async () => ({ conversationId } as never)),
      submit: vi.fn(async () => ({ taskRunId, streamVersion: 2 as const })),
      ...overrides,
    },
    global: { plugins: [router] },
  })
  return { wrapper, router }
}

describe('workspace TaskRun composer', () => {
  it('opens the canonical conversation, submits once, and navigates to the queued run', async () => {
    const openConversation = vi.fn(async () => ({ conversationId } as never))
    const submit = vi.fn(async () => ({ taskRunId, streamVersion: 2 as const }))
    const { wrapper, router } = await mountComposer({ openConversation, submit })
    await wrapper.get('textarea').setValue('Build the feature')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(openConversation).toHaveBeenCalledWith(workspaceId)
    expect(submit).toHaveBeenCalledWith(conversationId, workspaceId, 'Build the feature')
    expect(router.currentRoute.value.path).toBe(`/task-runs/${taskRunId}`)
    expect(wrapper.get('textarea').element.value).toBe('')
  })

  it('preserves the draft and shows a recovery action when submission fails', async () => {
    const submit = vi.fn(async () => { throw new Error('offline') })
    const { wrapper, router } = await mountComposer({ submit })
    await wrapper.get('textarea').setValue('Keep this request')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.get('textarea').element.value).toBe('Keep this request')
    expect(wrapper.get('[role="alert"]').text()).toContain('Check the runtime connection and try again')
    expect(router.currentRoute.value.path).toBe(`/workspaces/${workspaceId}`)
  })

  it('does not submit when runtime mutation is unavailable', async () => {
    const submit = vi.fn()
    const { wrapper } = await mountComposer({ disabled: true, submit })
    await wrapper.get('textarea').setValue('Draft')
    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
    expect(submit).not.toHaveBeenCalled()
  })

  it('rejects an oversized UTF-8 prompt before opening a conversation', async () => {
    const openConversation = vi.fn(async () => ({ conversationId } as never))
    const submit = vi.fn(async () => ({ taskRunId, streamVersion: 2 as const }))
    const { wrapper } = await mountComposer({ openConversation, submit })
    await wrapper.get('textarea').setValue('🌍'.repeat(16_385))

    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[role="alert"]').text()).toContain('64 KiB or less')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(openConversation).not.toHaveBeenCalled()
    expect(submit).not.toHaveBeenCalled()
  })

  it('cancels submission when the workspace changes during open', async () => {
    let resolveConversation: ((value: { conversationId: string }) => void) | undefined
    const openConversation = vi.fn(() => new Promise<{ conversationId: string }>((resolve) => {
      resolveConversation = resolve
    }))
    const submit = vi.fn(async () => ({ taskRunId, streamVersion: 2 as const }))
    const { wrapper } = await mountComposer({ openConversation, submit })
    await wrapper.get('textarea').setValue('Build the feature')
    const pending = wrapper.get('form').trigger('submit')
    await flushPromises()
    await wrapper.setProps({ workspaceId: '018f2e3a-7000-7000-8000-000000000213' })
    resolveConversation?.({ conversationId })
    await pending
    await flushPromises()

    expect(openConversation).toHaveBeenCalledWith(workspaceId)
    expect(submit).not.toHaveBeenCalled()
    expect(wrapper.get('textarea').element.value).toBe('Build the feature')
    expect(wrapper.get('[role="alert"]').text()).toContain('workspace changed')
  })
})
