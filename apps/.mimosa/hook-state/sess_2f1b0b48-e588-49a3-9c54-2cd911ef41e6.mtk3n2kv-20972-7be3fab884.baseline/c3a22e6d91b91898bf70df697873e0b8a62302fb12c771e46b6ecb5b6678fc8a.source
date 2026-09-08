import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import ProjectsPage from './ProjectsPage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  displayName: 'gocode-ui',
  version: 1,
  archived: false,
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

function mountWithRuntimeSession(
  componentProps: { readonly loadProjects: () => Promise<readonly typeof project[]> },
  router: ReturnType<typeof createTestRouter>,
) {
  const Harness = defineComponent({
    setup() {
      provideRuntimeSession(liveContext())
      return () => h(ProjectsPage, componentProps)
    },
  })
  return mount(Harness, { global: { plugins: [router] } })
}

function createTestRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: ProjectsPage },
      {
        path: '/projects/:projectId',
        name: 'project-details',
        component: { template: '<div>Project details</div>' },
      },
      {
        path: '/projects/open',
        name: 'open-project',
        component: { template: '<div>Open project</div>' },
      },
    ],
  })
}

describe('projects page', () => {
  it('waits for the injected runtime session before loading canonical projects', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const snapshot = shallowRef<RuntimeSessionSnapshot>({
      runtime: 'unconfigured', status: 'empty', canMutate: false,
    })
    const context: RuntimeSessionContext = {
      snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>,
      connect: async () => snapshot.value,
      retry: async () => snapshot.value,
      close: async () => {},
      observeBootstrap: () => snapshot.value,
    }
    let loads = 0
    const Harness = defineComponent({
      setup() {
        provideRuntimeSession(context)
        return () => h(ProjectsPage, {
          loadProjects: async () => {
            loads += 1
            return [project]
          },
        })
      },
    })
    mount(Harness, { global: { plugins: [router] } })
    await flushPromises()

    expect(loads).toBe(0)
    snapshot.value = { runtime: 'live', status: 'live', canMutate: true }
    await flushPromises()

    expect(loads).toBe(1)
  })

  it('renders persisted projects and opens their project details route', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mountWithRuntimeSession({ loadProjects: async () => [project] }, router)
    await flushPromises()

    expect(wrapper.text()).toContain('gocode-ui')
    expect(wrapper.text()).not.toContain('/workspace/gocode-ui')
    expect(wrapper.get('[aria-label="Open project gocode-ui"]').attributes('type')).toBe('button')
    expect(wrapper.get('[aria-labelledby="recent-projects-title"]').text()).toContain('Recent')
    expect(wrapper.get('.projects-page__header .gc-button').text()).toContain('Open local project')
    expect(wrapper.find('.runtime-summary').exists()).toBe(false)
    expect(wrapper.findAll('.project-card--open[aria-label="Open local project"] svg')).toHaveLength(2)
    expect(wrapper.findAll('[aria-label="Open project gocode-ui"] svg')).toHaveLength(2)

    await wrapper.get('[aria-label="Open project gocode-ui"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe(`/projects/${project.projectId}`)
  })

  it('opens the documented local project setup route', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mountWithRuntimeSession({ loadProjects: async () => [] }, router)
    await flushPromises()

    await wrapper.get('[aria-label="Open local project"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/projects/open')
  })

  it('fails closed without a runtime session provider', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    let loads = 0
    const wrapper = mount(ProjectsPage, {
      props: {
        loadProjects: async () => {
          loads += 1
          return [project]
        },
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    expect(loads).toBe(0)
    expect(wrapper.get('[role="alert"]').text()).toContain('Projects unavailable')
    expect(wrapper.html()).not.toContain('/Users/')
  })

  it('redacts paths from rejected project loading', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mountWithRuntimeSession({
      loadProjects: async () => { throw new Error('/Users/private/project') },
    }, router)
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Projects could not be loaded.')
    expect(wrapper.html()).not.toContain('private/project')
  })

  it('keeps loading and empty recent-project states accessible', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    let resolveProjects: ((projects: readonly typeof project[]) => void) | undefined
    const wrapper = mountWithRuntimeSession({
      loadProjects: () => new Promise(resolve => { resolveProjects = resolve }),
    }, router)
    await flushPromises()

    expect(wrapper.get('[aria-live="polite"]').text()).toContain('Loading projects')
    resolveProjects?.([])
    await flushPromises()

    expect(wrapper.text()).toContain('No projects')
  })
})
