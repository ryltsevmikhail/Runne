import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import OpenProjectPage from './OpenProjectPage.vue'

const selection = { reference: 'a'.repeat(64) } as const

function createTestRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/projects/open', component: OpenProjectPage },
      {
        path: '/projects/:projectId',
        name: 'project-details',
        component: { template: '<div>Project details</div>' },
      },
    ],
  })
}

describe('open project page', () => {
  it('retains only an opaque host selection pending workspace preparation', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    const wrapper = mount(OpenProjectPage, {
      props: { openProject: async () => selection },
      global: { plugins: [router] },
    })

    await wrapper.get('[aria-label="Choose project folder"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/projects/open')
    expect(wrapper.text()).toContain('Folder selected. Choose a workspace to continue.')
  })

  it('fails closed without exposing a rejected local path', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    const wrapper = mount(OpenProjectPage, {
      props: {
        openProject: async () => {
          throw new Error('/Users/private/secret-project')
        },
      },
      global: { plugins: [router] },
    })

    await wrapper.get('[aria-label="Choose project folder"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toBe('The selected folder could not be opened.')
    expect(wrapper.html()).not.toContain('secret-project')
  })
})
