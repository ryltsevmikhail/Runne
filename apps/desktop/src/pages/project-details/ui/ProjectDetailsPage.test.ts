import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import ProjectDetailsPage from './ProjectDetailsPage.vue'

const project = {
  id: 7,
  name: 'gocode-ui',
  path: '/workspace/gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

async function mountPage(loadProject: (id: number) => Promise<typeof project | null>) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/projects/:id', component: ProjectDetailsPage },
      { path: '/workspaces/:id', name: 'workspace', component: { template: '<div>Workspace</div>' } },
    ],
  })
  await router.push('/projects/7')
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
    const { router, wrapper } = await mountPage(async () => project)

    expect(wrapper.get('h1').text()).toBe('gocode-ui')
    expect(wrapper.text()).toContain('/workspace/gocode-ui')

    await wrapper.get('[aria-label="Open workspace gocode-ui"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/workspaces/7')
  })

  it('fails closed when the project is unavailable', async () => {
    const { wrapper } = await mountPage(async () => null)

    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
    expect(wrapper.find('[aria-label^="Open workspace"]').exists()).toBe(false)
  })
})
