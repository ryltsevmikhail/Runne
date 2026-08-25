import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { CanonicalProjectDetails } from '@/entities/project'

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

async function mountPage(loadProject: (id: string) => Promise<CanonicalProjectDetails>) {
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
      return () => h(ProjectDetailsPage, { loadProject })
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router] } })
  await flushPromises()
  return { router, wrapper }
}

describe('project details page', () => {
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

  it('fails closed when the project is unavailable', async () => {
    const { wrapper } = await mountPage(async () => {
      throw new Error('unavailable')
    })

    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
    expect(wrapper.find('[aria-label^="Open workspace"]').exists()).toBe(false)
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
