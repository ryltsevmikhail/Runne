import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const native = vi.hoisted(() => ({ invoke: vi.fn(), isTauri: vi.fn(() => false) }))

vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke, isTauri: native.isTauri }))

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { CanonicalProject } from '@/entities/project'
import SidebarProjects from './SidebarProjects.vue'

const project = { projectId: '01890e00-0000-7000-8000-000000000001', displayName: 'runne', version: 1, archived: false } as const
const workspace = { workspaceId: '01890e00-0000-7000-8000-000000000002', projectId: project.projectId, displayName: 'editor', version: 1, open: false } as const

function session(status: RuntimeSessionSnapshot['status'] = 'live') {
  const snapshot = shallowRef<RuntimeSessionSnapshot>({ runtime: status === 'live' ? 'live' : null, status, canMutate: status === 'live' })
  const context: RuntimeSessionContext = {
    snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>,
    connect: async () => snapshot.value,
    retry: async () => snapshot.value,
    close: async () => {},
    observeBootstrap: () => snapshot.value,
    sessionTicket: () => 0,
    ticketFenced: () => false,
  }
  return { context, snapshot }
}

async function mountSidebar(
  options: Partial<InstanceType<typeof SidebarProjects>['$props']> = {},
  status: RuntimeSessionSnapshot['status'] = 'live',
  initialPath = '/',
) {
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/projects/:projectId', name: 'project-details', component: { template: '<div />' } },
    { path: '/workspaces/:workspaceId', name: 'workspace', component: { template: '<div />' } },
    { path: '/text-chat', name: 'text-chat', component: { template: '<div />' } },
  ] })
  await router.push(initialPath)
  await router.isReady()
  const runtime = session(status)
  const Harness = defineComponent({
    setup: () => {
      provideRuntimeSession(runtime.context)
      return () => h(SidebarProjects, { collapsed: false, ...options })
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router, runtime }
}

describe('SidebarProjects', () => {
  beforeEach(() => { native.invoke.mockReset(); native.isTauri.mockReturnValue(false) })

  it('uses the canonical project list and renders a compact tree row', async () => {
    native.invoke.mockResolvedValue([project])
    const { wrapper } = await mountSidebar()

    expect(native.invoke).toHaveBeenCalledWith('list_canonical_projects')
    expect(wrapper.get('[aria-label="Open project runne"]').isVisible()).toBe(true)
    expect(wrapper.find('.project-tree-children').exists()).toBe(false)
  })

  it('fails closed until runtime is live, then lists projects', async () => {
    const loadProjects = vi.fn(async () => [project])
    const { wrapper, runtime } = await mountSidebar({ loadProjects }, 'unavailable')

    expect(wrapper.get('[role="alert"]').text()).toContain('Runtime session is unavailable')
    expect(loadProjects).not.toHaveBeenCalled()
    runtime.snapshot.value = { runtime: 'live', status: 'live', canMutate: true }
    await flushPromises()

    expect(wrapper.text()).toContain('runne')
    expect(loadProjects).toHaveBeenCalledOnce()
  })

  it('does not render a stale project list after a route refresh', async () => {
    let resolveFirst: ((value: readonly CanonicalProject[]) => void) | undefined
    const loadProjects = vi.fn()
      .mockImplementationOnce(() => new Promise<readonly CanonicalProject[]>(resolve => { resolveFirst = resolve }))
      .mockResolvedValueOnce([project])
    const { wrapper, router } = await mountSidebar({ loadProjects })

    await router.push(`/?project=${project.projectId}`)
    await flushPromises()
    resolveFirst?.([{ ...project, displayName: 'stale' }])
    await flushPromises()

    expect(wrapper.text()).toContain('runne')
    expect(wrapper.text()).not.toContain('stale')
  })

  it('keeps archived projects visible and clears rows on runtime loss', async () => {
    const archived = { ...project, archived: true }
    const { wrapper, runtime } = await mountSidebar({ loadProjects: async () => [archived] })

    await wrapper.get('[aria-label="Expand project tree for runne"]').trigger('click')
    expect(wrapper.get('.project-tree-note').text()).toContain('Archived')
    runtime.snapshot.value = { runtime: null, status: 'unavailable', canMutate: false }
    await flushPromises()

    expect(wrapper.findAll('.sidebar-projects__list > li')).toHaveLength(0)
    expect(wrapper.get('[role="alert"]').text()).toContain('Runtime session is unavailable')
  })

  it('expands a project and opens a selected workspace', async () => {
    const loadProject = vi.fn(async () => ({ project, workspaces: [workspace] }))
    const openWorkspace = vi.fn(async () => ({ workspaceId: workspace.workspaceId, newVersion: 2 }))
    const loadWorkspace = vi.fn(async () => workspace)
    const { wrapper, router } = await mountSidebar({
      loadProjects: async () => [project],
      loadProject,
      loadWorkspace,
      openWorkspace,
    })

    await wrapper.get('[aria-label="Expand project tree for runne"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[aria-label="Open workspace editor"]')).toBeTruthy()

    await wrapper.get('[aria-label="Open workspace editor"]').trigger('click')
    await flushPromises()

    expect(openWorkspace).toHaveBeenCalledWith(workspace.workspaceId, workspace.version)
    expect(router.currentRoute.value.name).toBe('workspace')
    expect(router.currentRoute.value.params.workspaceId).toBe(workspace.workspaceId)
  })

  it('opens a project with one workspace in one click', async () => {
    const openWorkspace = vi.fn(async () => ({ workspaceId: workspace.workspaceId, newVersion: 2 }))
    const { wrapper, router } = await mountSidebar({
      loadProjects: async () => [project],
      loadProject: async () => ({ project, workspaces: [{ ...workspace, open: true }] }),
      openWorkspace,
    })

    await wrapper.get('[aria-label="Open project runne"]').trigger('click')
    await flushPromises()

    expect(openWorkspace).not.toHaveBeenCalled()
    expect(router.currentRoute.value.name).toBe('workspace')
    expect(router.currentRoute.value.params.workspaceId).toBe(workspace.workspaceId)
  })

  it('shows a collapsed direct-open failure and retries the same action', async () => {
    let attempts = 0
    const loadProject = vi.fn(async () => {
      attempts += 1
      if (attempts === 1) throw new Error('temporary')
      return { project, workspaces: [{ ...workspace, open: true }] }
    })
    const { wrapper, router } = await mountSidebar({
      loadProjects: async () => [project],
      loadProject,
    })

    await wrapper.get('[aria-label="Open project runne"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('workspace could not be opened')

    await wrapper.get('.project-tree-open-error').trigger('click')
    await flushPromises()
    expect(loadProject).toHaveBeenCalledTimes(2)
    expect(router.currentRoute.value.name).toBe('workspace')
  })

  it('expands the project selected by the route query', async () => {
    const loadProject = vi.fn(async () => ({ project, workspaces: [workspace] }))
    const { wrapper } = await mountSidebar({
      loadProjects: async () => [project],
      loadProject,
    }, 'live', `/?project=${project.projectId}`)

    expect(wrapper.get(`[aria-label="Open project ${project.displayName}"]`).attributes('aria-current')).toBe('page')
    expect(wrapper.get('[aria-label="Open workspace editor"]')).toBeTruthy()
    expect(loadProject).toHaveBeenCalledWith(project.projectId)
  })

  it('reports an unavailable project target after the canonical list loads', async () => {
    const { wrapper } = await mountSidebar({
      loadProjects: async () => [project],
    }, 'live', '/?project=01890e00-0000-7000-8000-000000000099')

    expect(wrapper.get('[role="alert"]').text()).toContain('This project is no longer available')
  })

  it('resolves the active project from a workspace route', async () => {
    const loadWorkspace = vi.fn(async () => ({ ...workspace, open: true }))
    const { wrapper } = await mountSidebar({
      loadProjects: async () => [project],
      loadWorkspace,
      loadProject: async () => ({ project, workspaces: [{ ...workspace, open: true }] }),
    }, 'live', `/workspaces/${workspace.workspaceId}`)

    expect(loadWorkspace).toHaveBeenCalledWith(workspace.workspaceId)
    expect(wrapper.get(`[aria-label="Open project ${project.displayName}"]`).attributes('aria-current')).toBeUndefined()
    expect(wrapper.get('[aria-label="Open workspace editor"]').attributes('aria-current')).toBe('page')
    expect(wrapper.findAll('[aria-current="page"]')).toHaveLength(1)
  })

  it('uses the workspace owner over a conflicting project query', async () => {
    const other = { ...project, projectId: '01890e00-0000-7000-8000-000000000009', displayName: 'other' }
    const loadWorkspace = vi.fn(async () => ({ ...workspace, open: true }))
    const { wrapper } = await mountSidebar({
      loadProjects: async () => [project, other],
      loadWorkspace,
      loadProject: async current => current === project.projectId
        ? { project, workspaces: [{ ...workspace, open: true }] }
        : { project: other, workspaces: [] },
    }, 'live', `/workspaces/${workspace.workspaceId}?project=${other.projectId}`)

    expect(wrapper.get(`[aria-label="Open project ${project.displayName}"]`).classes()).toContain('project-tree-open--active')
    expect(wrapper.get(`[aria-label="Open project ${other.displayName}"]`).classes()).not.toContain('project-tree-open--active')
  })

  it('keeps project mutations disabled until workspace ownership is resolved', async () => {
    const loadWorkspace = vi.fn(async () => { throw new Error('owner unavailable') })
    const { wrapper } = await mountSidebar({
      loadProjects: async () => [project],
      loadWorkspace,
    }, 'live', `/workspaces/${workspace.workspaceId}`)

    expect(loadWorkspace).toHaveBeenCalledWith(workspace.workspaceId)
    expect(wrapper.get('.project-menu__trigger').attributes('disabled')).toBeDefined()
  })

  it('creates a workspace from an expanded project', async () => {
    const created = { workspaceId: workspace.workspaceId, newVersion: 1 }
    const createWorkspace = vi.fn(async () => created)
    const { wrapper, router } = await mountSidebar({
      loadProjects: async () => [project],
      loadProject: async () => ({ project, workspaces: [] }),
      createWorkspace,
    })

    await wrapper.get('[aria-label="Expand project tree for runne"]').trigger('click')
    await flushPromises()
    await wrapper.get('button.project-tree-create').trigger('click')
    await flushPromises()

    expect(createWorkspace).toHaveBeenCalledWith(project.projectId, 'Workspace')
    expect(router.currentRoute.value.name).toBe('workspace')
  })
})
