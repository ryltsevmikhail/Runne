import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { CanonicalProjectDetails, CanonicalProjectDestructiveOperation } from '@/entities/project'

import ProjectDetailsPage from './ProjectDetailsPage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  displayName: 'gocode-ui',
  version: 1,
  archived: false,
} as const
const workspace = {
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  projectId: project.projectId,
  displayName: 'gocode-ui',
  version: 1,
  open: true,
} as const
const details = { project, workspaces: [workspace] } as const
const emptyDetails = { project, workspaces: [] } as const

function liveContext(): RuntimeSessionContext {
  const snapshot = shallowRef<RuntimeSessionSnapshot>({
    runtime: 'live', status: 'live', canMutate: true,
  })
  return {
    snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>,
    connect: async () => snapshot.value,
    retry: async () => snapshot.value,
    close: async () => {},
    observeBootstrap: () => snapshot.value,
  }
}

async function mountPage(
  loadProject: (id: string) => Promise<CanonicalProjectDetails>,
  createWorkspace: (projectId: string, displayName: string) => Promise<{ workspaceId: string; newVersion: number }> = async () => ({ workspaceId: workspace.workspaceId, newVersion: 1 }),
  openWorkspace: (workspaceId: string, expectedVersion: number) => Promise<{ workspaceId: string; newVersion: number }> = async () => ({ workspaceId: workspace.workspaceId, newVersion: 2 }),
  destructiveAction: (_projectId: string, _expectedVersion: number, _operation: CanonicalProjectDestructiveOperation) => Promise<void> = async () => {},
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/projects/:projectId', component: ProjectDetailsPage },
      { path: '/workspaces/:workspaceId', name: 'workspace', component: { template: '<div>Workspace</div>' } },
    ],
  })
  await router.push(`/projects/${project.projectId}`)
  await router.isReady()
  const Harness = defineComponent({
    setup() {
      provideRuntimeSession(liveContext())
      return () => h(ProjectDetailsPage, {
        loadProject,
        createWorkspaceMutation: createWorkspace,
        openWorkspaceMutation: openWorkspace,
        destructiveProjectAction: destructiveAction,
      })
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router] } })
  await flushPromises()
  return { router, wrapper }
}

describe('project details page', () => {
  it('offers a runtime workspace creation action for an empty project', async () => {
    const { wrapper } = await mountPage(async () => emptyDetails)

    expect(wrapper.find('[aria-label="Create workspace"]').exists()).toBe(true)
  })

  it('refreshes the authoritative project after creating a workspace', async () => {
    let reads = 0
    let created: [string, string] | null = null
    const { wrapper } = await mountPage(
      async () => {
        reads += 1
        return reads === 1 ? emptyDetails : details
      },
      async (projectId, displayName) => {
        created = [projectId, displayName]
        return { workspaceId: workspace.workspaceId, newVersion: 1 }
      },
    )

    await wrapper.get('[aria-label="Create workspace"]').trigger('click')
    await flushPromises()
    expect(created).toEqual([project.projectId, 'Workspace'])
    expect(wrapper.find('[aria-label="Open workspace gocode-ui"]').exists()).toBe(true)
  })

  it('does not restore a project from a legacy numeric route ID', async () => {
    const requestedIds: string[] = []
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/', component: { template: '<div>Projects</div>' } },
        { path: '/projects/:projectId', component: ProjectDetailsPage },
      ],
    })
    await router.push('/projects/7')
    await router.isReady()
    const Harness = defineComponent({
      setup() {
        provideRuntimeSession(liveContext())
        return () => h(ProjectDetailsPage, {
          loadProject: async id => {
            requestedIds.push(id)
            return details
          },
        })
      },
    })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()

    expect(requestedIds).toEqual([])
    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
  })

  it('renders the persisted project and opens its local workspace', async () => {
    const { router, wrapper } = await mountPage(async () => details)

    expect(wrapper.get('h1').text()).toBe('gocode-ui')
    expect(wrapper.text()).not.toContain('/workspace/gocode-ui')

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe(`/workspaces/${workspace.workspaceId}`)
  })

  it('routes each workspace using its own canonical workspace ID', async () => {
    const otherWorkspace = {
      workspaceId: '01890e00-0000-7000-8000-000000000003',
      projectId: project.projectId,
      displayName: 'gocode-docs',
      version: 1,
      open: false,
    } as const
    const { router, wrapper } = await mountPage(async () => ({
      project,
      workspaces: [workspace, otherWorkspace],
    }))

    await wrapper.get('[aria-label="Open workspace gocode-docs"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe(`/workspaces/${otherWorkspace.workspaceId}`)
  })

  it('opens a closed workspace through the exact-version mutation before routing', async () => {
    const closedWorkspace = { ...workspace, open: false, version: 4 } as const
    let opened: [string, number] | null = null
    const { router, wrapper } = await mountPage(
      async () => ({ project, workspaces: [closedWorkspace] }),
      undefined,
      async (workspaceId, expectedVersion) => {
        opened = [workspaceId, expectedVersion]
        return { workspaceId, newVersion: expectedVersion + 1 }
      },
    )

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()

    expect(opened).toEqual([closedWorkspace.workspaceId, closedWorkspace.version])
    expect(router.currentRoute.value.fullPath).toBe(`/workspaces/${closedWorkspace.workspaceId}`)
  })

  it('does not route to a workspace after leaving the project while it is opening', async () => {
    const closedWorkspace = { ...workspace, open: false } as const
    let resolveOpen: ((value: { workspaceId: string; newVersion: number }) => void) | undefined
    const { router, wrapper } = await mountPage(
      async () => ({ project, workspaces: [closedWorkspace] }),
      undefined,
      () => new Promise(resolve => { resolveOpen = resolve }),
    )

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()
    await router.push('/')
    resolveOpen?.({ workspaceId: closedWorkspace.workspaceId, newVersion: closedWorkspace.version + 1 })
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/')
  })

  it('keeps the current project route when a previous workspace open resolves late', async () => {
    const otherProject = { ...project, projectId: '01890e00-0000-7000-8000-000000000009', displayName: 'Other' } as const
    const otherWorkspace = { ...workspace, projectId: otherProject.projectId, workspaceId: '01890e00-0000-7000-8000-000000000010', open: true } as const
    let resolveOpen: ((value: { workspaceId: string; newVersion: number }) => void) | undefined
    let reads = 0
    const { router, wrapper } = await mountPage(
      async id => {
        reads += 1
        return id === otherProject.projectId
          ? { project: otherProject, workspaces: [otherWorkspace] }
          : { project, workspaces: [{ ...workspace, open: false }] }
      },
      undefined,
      () => new Promise(resolve => { resolveOpen = resolve }),
    )

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()
    await router.push(`/projects/${otherProject.projectId}`)
    await flushPromises()
    const readsAfterNavigation = reads
    resolveOpen?.({ workspaceId: workspace.workspaceId, newVersion: workspace.version + 1 })
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe(`/projects/${otherProject.projectId}`)
    expect(wrapper.get('h1').text()).toBe('Other')
    expect(reads).toBe(readsAfterNavigation)
  })

  it('fails closed when the project is unavailable', async () => {
    const { wrapper } = await mountPage(async () => {
      throw new Error('unavailable')
    })

    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
    expect(wrapper.find('[aria-label^="Open workspace"]').exists()).toBe(false)
  })

  it('dispatches archive through the native destructive intent boundary', async () => {
    let action: [string, number, CanonicalProjectDestructiveOperation] | null = null
    const { wrapper } = await mountPage(
      async () => details,
      undefined,
      undefined,
      async (projectId, expectedVersion, operation) => {
        action = [projectId, expectedVersion, operation]
      },
    )

    await wrapper.get('[aria-label="Manage project"]').trigger('click')
    await wrapper.get('[aria-label="Archive project"]').trigger('click')
    expect(action).toBeNull()
    const cancel = document.body.querySelector('.gc-dialog-btn--cancel') as HTMLButtonElement | null
    expect(cancel).not.toBeNull()
    expect(document.activeElement).toBe(cancel)
    cancel?.click()
    await flushPromises()
    expect(action).toBeNull()

    await wrapper.get('[aria-label="Manage project"]').trigger('click')
    await wrapper.get('[aria-label="Archive project"]').trigger('click')
    const confirm = document.body.querySelector('.gc-dialog-btn:not(.gc-dialog-btn--cancel)') as HTMLButtonElement | null
    expect(confirm).not.toBeNull()
    confirm?.click()
    await flushPromises()

    expect(action).toEqual([project.projectId, project.version, 'archive'])
  })

  it('does not redirect after a stale delete completion changes the project route', async () => {
    const otherProject = { ...project, projectId: '01890e00-0000-7000-8000-000000000009', displayName: 'Other' } as const
    let resolveDelete: (() => void) | undefined
    let reads = 0
    const { router, wrapper } = await mountPage(
      async id => {
        reads += 1
        return id === otherProject.projectId
          ? { project: otherProject, workspaces: [] }
          : details
      },
      undefined,
      undefined,
      async () => new Promise<void>(resolve => { resolveDelete = resolve }),
    )

    await wrapper.get('[aria-label="Manage project"]').trigger('click')
    await wrapper.get('[aria-label="Delete project"]').trigger('click')
    const confirm = document.body.querySelector('.gc-dialog-btn:not(.gc-dialog-btn--cancel)') as HTMLButtonElement | null
    expect(confirm).not.toBeNull()
    confirm?.click()
    await flushPromises()

    await router.push(`/projects/${otherProject.projectId}`)
    await flushPromises()
    const readsAfterNavigation = reads
    resolveDelete?.()
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe(`/projects/${otherProject.projectId}`)
    expect(wrapper.get('h1').text()).toBe('Other')
    expect(reads).toBe(readsAfterNavigation)
  })

  it('reloads on project navigation and discards a late previous project response', async () => {
    const other = { ...project, projectId: '01890e00-0000-7000-8000-000000000009', displayName: 'Other' }
    let resolveOld: ((value: CanonicalProjectDetails) => void) | undefined
    let reads = 0
    const { wrapper, router } = await mountPage(async id => {
      if (id === other.projectId) return { project: other, workspaces: [] }
      if (++reads === 1) return details
      return new Promise(resolve => { resolveOld = resolve })
    })
    await router.push(`/projects/${other.projectId}`)
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe('Other')
    await router.push(`/projects/${project.projectId}`)
    await flushPromises()
    await router.push(`/projects/${other.projectId}`)
    await flushPromises()
    resolveOld?.(details)
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe('Other')
  })

  it('fails closed without a runtime session provider', async () => {
    let requests = 0
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/projects/:projectId', component: ProjectDetailsPage }],
    })
    await router.push(`/projects/${project.projectId}`)
    await router.isReady()
    const wrapper = mount(ProjectDetailsPage, {
      props: {
        loadProject: async () => {
          requests += 1
          return details
        },
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    expect(requests).toBe(0)
    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
  })
})
