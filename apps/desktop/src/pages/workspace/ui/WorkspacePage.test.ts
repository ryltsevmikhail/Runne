import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Component, type Ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { CanonicalWorkspace } from '@/entities/project'
import type { WorkspaceFileEntry } from '@/entities/file-tree'
import { currentLocale } from '@/shared/i18n'
import type { WorkspaceRefreshLoaders } from '../model/workspace-refresh'
import WorkspacePage from './WorkspacePage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  version: 1,
  open: true,
} as const

const projectA = project
const projectB = {
  ...project,
  workspaceId: '01890e00-0000-7000-8000-000000000003',
  displayName: 'runne-cli',
} as const
const WORKSPACE_A = projectA.workspaceId
const WORKSPACE_B = projectB.workspaceId

type Loaders = WorkspaceRefreshLoaders
type LoaderOverrides = Partial<Loaders> & Pick<Loaders, 'loadProject'>

const emptyFiles: Loaders['loadFiles'] = async () => ({ items: [] })
const emptyChanges: Loaders['loadChanges'] = async () => ({ items: [] })
const emptyDiff: Loaders['loadDiff'] = async () => ({ path: '', kind: 'modified', hunks: [], truncated: false })

function mutableRuntimeContext() {
  const snapshot = shallowRef<RuntimeSessionSnapshot>({
    runtime: 'live', status: 'live', canMutate: true,
  })
  const context: RuntimeSessionContext = {
    snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>,
    connect: async () => snapshot.value,
    retry: async () => snapshot.value,
    close: async () => {},
    observeBootstrap: () => snapshot.value,
    sessionTicket: () => 0,
    ticketFenced: () => false,
  }
  return {
    context,
    set(next: Partial<RuntimeSessionSnapshot>) {
      snapshot.value = { ...snapshot.value, ...next }
    },
  }
}

async function mountPageWith(
  loaders: LoaderOverrides,
  runtime = mutableRuntimeContext(),
  stubs: Record<string, Component> = {},
  initialWorkspaceId = WORKSPACE_A,
) {
  const props: Loaders = {
    loadProject: loaders.loadProject,
    loadFiles: loaders.loadFiles ?? emptyFiles,
    loadChanges: loaders.loadChanges ?? emptyChanges,
    loadDiff: loaders.loadDiff ?? emptyDiff,
  }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/projects/:projectId', name: 'project-details', component: { template: '<div>Project details</div>' } },
      { path: '/workspaces/:workspaceId', name: 'workspace', component: WorkspacePage },
    ],
  })
  await router.push(`/workspaces/${initialWorkspaceId}`)
  await router.isReady()
  const Harness = defineComponent({
    setup() {
      provideRuntimeSession(runtime.context)
      return () => h(WorkspacePage, props)
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router], stubs } })
  await flushPromises()
  return { wrapper, router, runtime }
}

async function mountWorkspace(
  loadProject: (id: string) => Promise<CanonicalWorkspace>,
  loadFiles: (id: string, path: string, limit: number) => Promise<{
    readonly items: readonly WorkspaceFileEntry[]
  }> = async () => ({ items: [] }),
) {
  return (await mountPageWith({ loadProject, loadFiles })).wrapper
}

describe('workspace page', () => {
  it('restores the persisted project identified by the route', async () => {
    const requestedIds: string[] = []
    const wrapper = await mountWorkspace(async (id) => {
      requestedIds.push(id)
      return project
    })

    expect(project.projectId).not.toBe(project.workspaceId)
    expect(requestedIds).toEqual([project.workspaceId])
    expect(wrapper.get('h1').text()).toBe('gocode-ui')
    expect(wrapper.text()).not.toContain('/workspace/gocode-ui')
    expect(wrapper.text()).toContain('Runtime workspace')
    expect(wrapper.text()).toContain('Runtime session controls this workspace')
    expect(wrapper.text()).toContain('Project tree')
    expect(wrapper.text()).toContain('No files in this workspace.')
    expect(wrapper.text()).toContain('Work area')
    expect(wrapper.text()).not.toContain('Workspace binding is prepared by the desktop host.')
  })

  it('exposes breadcrumb navigation and the workspace regions', async () => {
    const wrapper = await mountWorkspace(async () => project)

    const breadcrumb = wrapper.get('[aria-label="Workspace breadcrumb"]')
    expect(breadcrumb.text()).toContain('Projects')
    expect(breadcrumb.text()).toContain('gocode-ui')
    expect(breadcrumb.text()).toContain('Workspace')
    expect(breadcrumb.text()).not.toContain('›')
    expect(breadcrumb.findAll('svg')).toHaveLength(2)
    expect(wrapper.get('[aria-label="Project tree"]')).toBeTruthy()
    expect(wrapper.get('[aria-label="Conversation"]')).toBeTruthy()
    expect(wrapper.get('[aria-label="Details"]')).toBeTruthy()
  })

  it('localizes workspace region ARIA labels through the owned catalog', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = await mountWorkspace(async () => project)

      expect(wrapper.get('[aria-label="Дерево проекта"]')).toBeTruthy()
      expect(wrapper.get('[aria-label="Диалог"]')).toBeTruthy()
      expect(wrapper.get('[aria-label="Детали"]')).toBeTruthy()
    }
    finally {
      currentLocale.value = previousLocale
    }
  })

  it('renders the runtime-owned file projection', async () => {
    const wrapper = await mountWorkspace(async () => project, async () => ({
      items: [{ path: 'src/main.rs', kind: 'file', sizeBytes: 12 }],
    }))

    expect(wrapper.text()).toContain('src/main.rs')
    expect(wrapper.text()).not.toContain('Workspace files are unavailable.')
  })

  it('fails closed when the route project does not exist', async () => {
    const wrapper = await mountWorkspace(async () => {
      throw new Error('unavailable')
    })

    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
    expect(wrapper.text()).not.toContain('Runtime workspace')
  })

  it('fails closed without a runtime session provider', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/workspaces/:workspaceId', component: WorkspacePage }],
    })
    await router.push(`/workspaces/${project.workspaceId}`)
    await router.isReady()
    let requests = 0
    const wrapper = mount(WorkspacePage, {
      props: {
        loadProject: async () => {
          requests += 1
          return project
        },
        loadFiles: emptyFiles,
        loadChanges: emptyChanges,
        loadDiff: emptyDiff,
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    expect(requests).toBe(0)
    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
  })

  it('reloads the workspace when the router reuses the page and ignores an older response', async () => {
    let resolveA!: (value: typeof projectA) => void
    const loadProject = vi.fn((id: string) => id === WORKSPACE_A
      ? new Promise<typeof projectA>(resolve => { resolveA = resolve })
      : Promise.resolve(projectB))
    const loadFiles = vi.fn(emptyFiles)
    const loadChanges = vi.fn(emptyChanges)
    const { wrapper, router } = await mountPageWith({ loadProject, loadFiles, loadChanges })

    await router.push(`/workspaces/${WORKSPACE_B}`)
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe(projectB.displayName)
    expect(loadProject).toHaveBeenCalledWith(WORKSPACE_B)

    resolveA(projectA)
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe(projectB.displayName)
    expect(loadFiles).toHaveBeenCalledWith(WORKSPACE_B, '', 50)
    expect(loadChanges).toHaveBeenCalledWith(WORKSPACE_B, 50)
  })

})
