import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { WorkspaceFileEntry } from '@/entities/file-tree'
import WorkspacePage from './WorkspacePage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  version: 1,
  open: true,
} as const

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

async function mountWorkspace(
  loadProject: (id: string) => Promise<typeof project>,
  loadFiles: (id: string, path: string, limit: number) => Promise<{
    readonly items: readonly WorkspaceFileEntry[]
  }> = async () => ({ items: [] }),
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/workspaces/:workspaceId', name: 'workspace', component: WorkspacePage },
    ],
  })
  await router.push(`/workspaces/${project.workspaceId}`)
  await router.isReady()
  const Harness = defineComponent({
    setup() {
      provideRuntimeSession(liveContext())
      return () => h(WorkspacePage, { loadProject, loadFiles })
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router] } })
  await flushPromises()
  return wrapper
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
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    expect(requests).toBe(0)
    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
  })
})
