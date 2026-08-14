import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import type { Project } from '@/entities/project'

import ProjectDetailsPage from './ProjectDetailsPage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

async function mountPage(loadProject: (id: string) => Promise<readonly Project[]>) {
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
  const wrapper = mount(ProjectDetailsPage, {
    props: { loadProject },
    global: { plugins: [router] },
  })
  await flushPromises()
  return { router, wrapper }
}

describe('project details page', () => {
  it('renders the persisted project and opens its local workspace', async () => {
    const { router, wrapper } = await mountPage(async () => [project])

    expect(wrapper.get('h1').text()).toBe('gocode-ui')
    expect(wrapper.text()).not.toContain('/workspace/gocode-ui')

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe(`/workspaces/${project.workspaceId}`)
  })

  it('routes each workspace using its own canonical workspace ID', async () => {
    const otherWorkspace = {
      ...project,
      workspaceId: '01890e00-0000-7000-8000-000000000003',
      displayName: 'gocode-docs',
    } as const
    const { router, wrapper } = await mountPage(async () => [project, otherWorkspace])

    await wrapper.get('[aria-label="Open workspace gocode-docs"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe(`/workspaces/${otherWorkspace.workspaceId}`)
  })

  it('fails closed when the project is unavailable', async () => {
    const { wrapper } = await mountPage(async () => [])

    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
    expect(wrapper.find('[aria-label^="Open workspace"]').exists()).toBe(false)
  })
})
