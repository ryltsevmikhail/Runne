import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it, vi } from 'vitest'
import type { CanonicalProject, CanonicalProjectDetails } from '@/entities/project'
import type { ManagedTaskRunSummary } from '@/entities/task-run'
import TaskRunInventoryPage from './TaskRunInventoryPage.vue'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const taskRunId = '018f2e3a-7000-7000-8000-000000000210'
const project: CanonicalProject = { projectId, displayName: 'Engine', version: 1, archived: false }
const details: CanonicalProjectDetails = {
  project, workspaces: [{ workspaceId, projectId, displayName: 'Desktop', version: 1, open: true }],
}
const run: ManagedTaskRunSummary = {
  taskRunId, workspaceId, conversationId: null, state: 'succeeded', terminal: 'failure', streamVersion: 2, activeAttemptId: null,
}
async function mountPage(overrides: Record<string, unknown> = {}) {
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/task-runs', component: { template: '<div />' } },
    { path: '/approvals', name: 'approvals', component: { template: '<div />' } },
    { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
  ] })
  await router.push('/task-runs'); await router.isReady()
  const wrapper = mount(TaskRunInventoryPage, { props: {
    runtimeReady: true,
    loadRuns: async () => ({ status: 'available' as const, taskRuns: [run] }),
    loadProjects: async () => [project],
    loadProject: async () => details,
    ...overrides,
  }, global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router }
}

describe('TaskRunInventoryPage', () => {
  it('projects authoritative runs into Project → Workspace → TaskRun with canonical timeline links', async () => {
    const { wrapper } = await mountPage()
    expect(wrapper.text()).toContain('Project: Engine')
    expect(wrapper.text()).toContain('Workspace: Desktop')
    expect(wrapper.find(`a[href="/task-runs/${taskRunId}"]`).exists()).toBe(true)
    expect(wrapper.get('a[href="/approvals"]').text()).toBe('Attention inbox')
    expect(wrapper.text()).toContain('State: failure')
    expect(wrapper.find('[data-summary-value]').exists()).toBe(false)
  })

  it('keeps snapshots visibly unavailable and renders no invented task rows', async () => {
    const loadRuns = vi.fn(async () => ({ status: 'unavailable' as const, taskRuns: [] as [] }))
    const { wrapper } = await mountPage({ loadRuns })
    expect(loadRuns).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('Task run inventory is unavailable')
    expect(wrapper.find(`a[href="/task-runs/${taskRunId}"]`).exists()).toBe(false)
  })

  it('does not query runtime inventory when runtime authority is not live', async () => {
    const loadRuns = vi.fn()
    const { wrapper } = await mountPage({ runtimeReady: false, loadRuns })
    expect(loadRuns).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('Task run inventory is unavailable')
  })

  it('retains a deep link for a real run whose current workspace mapping is unavailable', async () => {
    const { wrapper } = await mountPage({ loadRuns: async () => ({ status: 'available' as const, taskRuns: [{ ...run, workspaceId: null }] }) })
    expect(wrapper.text()).toContain('Workspace association unavailable')
    expect(wrapper.get(`a[href="/task-runs/${taskRunId}"]`).attributes('href')).toBe(`/task-runs/${taskRunId}`)
  })

  it('discards a stale async snapshot when runtime goes unavailable', async () => {
    let resolve: ((value: { status: 'available', taskRuns: readonly ManagedTaskRunSummary[] }) => void) | undefined
    const loadRuns = vi.fn(() => new Promise<{ status: 'available', taskRuns: readonly ManagedTaskRunSummary[] }>(done => { resolve = done }))
    const { wrapper } = await mountPage({ loadRuns })
    await wrapper.setProps({ runtimeReady: false })
    resolve?.({ status: 'available', taskRuns: [run] }); await flushPromises()
    expect(wrapper.text()).toContain('Task run inventory is unavailable')
    expect(wrapper.find(`a[href="/task-runs/${taskRunId}"]`).exists()).toBe(false)
  })
})
