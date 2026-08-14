import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import ProjectsPage from './ProjectsPage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

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
  it('renders persisted projects and opens their project details route', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(ProjectsPage, {
      props: {
        loadProjects: async () => [project],
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('gocode-ui')
    expect(wrapper.text()).not.toContain('/workspace/gocode-ui')
    expect(wrapper.get('[aria-label="Open project gocode-ui"] button').attributes('type')).toBe('button')

    await wrapper.get('[aria-label="Open project gocode-ui"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe(`/projects/${project.projectId}`)
  })

  it('opens the documented local project setup route', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(ProjectsPage, {
      props: {
        loadProjects: async () => [],
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    await wrapper.get('[aria-label="Open local project"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/projects/open')
  })
})
