import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import ProjectsPage from './ProjectsPage.vue'

const project = {
  id: 7,
  name: 'gocode-ui',
  path: '/workspace/gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

function createTestRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: ProjectsPage },
      {
        path: '/workspaces/:id',
        name: 'workspace',
        component: { template: '<div>Workspace</div>' },
      },
    ],
  })
}

describe('projects page', () => {
  it('renders persisted projects and opens their workspace route', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(ProjectsPage, {
      props: {
        loadProjects: async () => [project],
        openProject: async () => null,
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('gocode-ui')
    expect(wrapper.text()).toContain('/workspace/gocode-ui')

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/workspaces/7')
  })

  it('opens the workspace returned by the native local project flow', async () => {
    const router = createTestRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(ProjectsPage, {
      props: {
        loadProjects: async () => [],
        openProject: async () => project,
      },
      global: { plugins: [router] },
    })
    await flushPromises()

    await wrapper.get('[aria-label="Open local project"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/workspaces/7')
  })
})
