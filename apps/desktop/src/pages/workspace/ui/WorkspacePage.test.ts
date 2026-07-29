import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import WorkspacePage from './WorkspacePage.vue'

const project = {
  id: 7,
  name: 'gocode-ui',
  path: '/workspace/gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

async function mountWorkspace(loadProject: (id: number) => Promise<typeof project | null>) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/workspaces/:id', name: 'workspace', component: WorkspacePage },
    ],
  })
  await router.push('/workspaces/7')
  await router.isReady()
  const wrapper = mount(WorkspacePage, {
    props: { loadProject },
    global: { plugins: [router] },
  })
  await flushPromises()
  return wrapper
}

describe('workspace page', () => {
  it('restores the persisted project identified by the route', async () => {
    const requestedIds: number[] = []
    const wrapper = await mountWorkspace(async (id) => {
      requestedIds.push(id)
      return project
    })

    expect(requestedIds).toEqual([7])
    expect(wrapper.get('h1').text()).toBe('gocode-ui')
    expect(wrapper.text()).toContain('/workspace/gocode-ui')
    expect(wrapper.text()).toContain('Local workspace')
    expect(wrapper.text()).toContain('Coding agent')
    expect(wrapper.text()).not.toContain('Nothing here yet')
  })

  it('fails closed when the route project does not exist', async () => {
    const wrapper = await mountWorkspace(async () => null)

    expect(wrapper.get('[role="alert"]').text()).toContain('Project unavailable')
    expect(wrapper.text()).not.toContain('Local workspace')
  })
})
