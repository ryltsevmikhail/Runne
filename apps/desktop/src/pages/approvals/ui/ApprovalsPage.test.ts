import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it, vi } from 'vitest'

import ApprovalsPage from './ApprovalsPage.vue'

const id = '018f2e3a-7000-7000-8000-000000000212'
const approval = { approvalId: id, taskRunId: id, attemptId: null, invocationId: id, action: 'fs:write', resource: 'workspace:/src/main.rs', actionDigest: '1'.repeat(64), policyRevision: 7, requestVersion: 3, expiresAt: 2_000, riskSummary: 'write source', state: 'pending' as const }

describe('ApprovalsPage', () => {
  it('renders the runtime-owned attention queue', async () => {
    const wrapper = mount(ApprovalsPage, { props: { runtimeReady: true, load: async () => [approval] } })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(wrapper.text()).toContain('fs:write')
    expect(wrapper.text()).toContain('workspace:/src/main.rs')
  })

  it('offers version-bound approve and deny actions and removes the acknowledged item', async () => {
    const decide = async () => ({ approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' as const })
    const wrapper = mount(ApprovalsPage, {
      props: { runtimeReady: true, load: async () => [approval], acquireGeneration: async () => 8, decide },
    })
    await new Promise(resolve => setTimeout(resolve, 0))
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    expect(wrapper.text()).toContain('No pending approvals.')
  })

  it('renders safe runtime attention projections as canonical TaskRun deep links', async () => {
    const attention = {
      status: 'available' as const, complete: false, items: [
        { approvalId: id, taskRunId: id, kind: 'approval' as const, workspaceId: null, conversationId: null },
        { approvalId: null, taskRunId: id, kind: 'uncertain' as const, workspaceId: id, conversationId: null },
        { approvalId: null, taskRunId: null, kind: 'effective_authority_unavailable' as const, workspaceId: null, conversationId: null },
      ],
    }
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/approvals', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push('/approvals'); await router.isReady()
    const wrapper = mount(ApprovalsPage, { props: { runtimeReady: true, load: async () => [], loadAttention: async () => attention }, global: { plugins: [router] } })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(wrapper.text()).toContain('Some runtime attention items are unavailable')
    expect(wrapper.text()).toContain('Task needs reconciliation')
    expect(wrapper.text()).toContain('Effective provider, model, and policy details are unavailable')
    expect(wrapper.findAll('a')).toHaveLength(2)
    expect(wrapper.findAll('a')[0]?.attributes('href')).toBe(`/task-runs/${id}`)
  })

  it('refreshes the authoritative Inbox after an approval acknowledgement', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/approvals', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push('/approvals'); await router.isReady()
    const attention = vi.fn()
      .mockResolvedValueOnce({ status: 'available', complete: true, items: [
        { approvalId: id, taskRunId: id, kind: 'approval', workspaceId: null, conversationId: null },
      ] })
      .mockResolvedValueOnce({ status: 'available', complete: true, items: [] })
    const decide = vi.fn(async () => ({ approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' as const }))
    const wrapper = mount(ApprovalsPage, {
      props: { runtimeReady: true, load: async () => [approval], loadAttention: attention, acquireGeneration: async () => 8, decide },
      global: { plugins: [router] },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Approval requires attention')
    expect(attention).toHaveBeenCalledTimes(1)

    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    await flushPromises()

    expect(decide).toHaveBeenCalledTimes(1)
    expect(attention).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).not.toContain('Approval requires attention')
    wrapper.unmount()
  })

  it('does not let an older Inbox snapshot overwrite the post-ack refresh', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/approvals', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push('/approvals'); await router.isReady()
    let resolveOldSnapshot: ((value: { status: 'available', complete: true, items: readonly unknown[] }) => void) | undefined
    const attention = vi.fn()
      .mockImplementationOnce(() => new Promise(resolve => { resolveOldSnapshot = resolve }))
      .mockResolvedValueOnce({ status: 'available', complete: true, items: [] })
    const wrapper = mount(ApprovalsPage, {
      props: {
        runtimeReady: true, load: async () => [approval], loadAttention: attention,
        acquireGeneration: async () => 8,
        decide: async () => ({ approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' as const }),
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    await flushPromises()
    resolveOldSnapshot?.({ status: 'available', complete: true, items: [
      { approvalId: id, taskRunId: id, kind: 'approval', workspaceId: null, conversationId: null },
    ] })
    await flushPromises()

    expect(attention).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).not.toContain('Approval requires attention')
    wrapper.unmount()
  })

  it('clears the old Inbox snapshot and shows unavailable when post-ack refresh fails', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/approvals', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push('/approvals'); await router.isReady()
    const attention = vi.fn()
      .mockResolvedValueOnce({ status: 'available', complete: true, items: [
        { approvalId: id, taskRunId: id, kind: 'approval', workspaceId: null, conversationId: null },
      ] })
      .mockRejectedValueOnce(new Error('runtime snapshot unavailable'))
    const wrapper = mount(ApprovalsPage, {
      props: {
        runtimeReady: true, load: async () => [approval], loadAttention: attention,
        acquireGeneration: async () => 8,
        decide: async () => ({ approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' as const }),
      },
      global: { plugins: [router] },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Approval requires attention')

    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).not.toContain('Approval requires attention')
    expect(wrapper.text()).toContain('Some runtime attention items are unavailable')
    wrapper.unmount()
  })

  it('does not query attention while runtime mutation authority is unavailable', async () => {
    const loadAttention = vi.fn()
    const wrapper = mount(ApprovalsPage, { props: { runtimeReady: false, load: async () => [], loadAttention } })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(loadAttention).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Some runtime attention items are unavailable')
  })

  it('releases an invalidated decision on disconnect without letting its late completion clear a newer one', async () => {
    const generations: Array<(value: number) => void> = []
    const acquireGeneration = vi.fn(() => new Promise<number>(resolve => generations.push(resolve)))
    const decide = vi.fn(async () => ({ approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' as const }))
    const wrapper = mount(ApprovalsPage, { props: {
      runtimeReady: true, load: async () => [approval], acquireGeneration, decide,
    } })
    await flushPromises()
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    await flushPromises()
    expect(generations).toHaveLength(1)

    await wrapper.setProps({ runtimeReady: false })
    await wrapper.setProps({ runtimeReady: true })
    await flushPromises()
    await wrapper.get('[data-approval-action="approve"]').trigger('click')
    await flushPromises()
    expect(generations).toHaveLength(2)

    generations[0]?.(8)
    await flushPromises()
    expect(decide).not.toHaveBeenCalled()
    generations[1]?.(9)
    await flushPromises()
    expect(decide).toHaveBeenCalledTimes(1)
    expect(decide).toHaveBeenCalledWith(approval, 'approve', 9)
  })
})
