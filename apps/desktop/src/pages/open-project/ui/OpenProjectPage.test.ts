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
      {
        path: '/workspaces/:workspaceId',
        name: 'workspace',
        component: { template: '<div>Workspace</div>' },
      },
    ],
  })
}

describe('open project page', () => {
  it('renders the native folder chooser with Lucide icons and a privacy notice', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    const wrapper = mount(OpenProjectPage, {
      props: { openProject: async () => null },
      global: { plugins: [router] },
    })

    expect(wrapper.find('.open-project-page').exists()).toBe(true)
    expect(wrapper.findAll('[aria-label="Choose project folder"] svg')).toHaveLength(2)
    expect(wrapper.text()).toContain('Runne stores only the local project record.')
    expect(wrapper.html()).not.toContain('IMPLEMENTED')
  })

  it('disables the chooser while the native picker is opening', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    let resolveOpen: ((result: null) => void) | undefined
    const wrapper = mount(OpenProjectPage, {
      props: {
        openProject: () => new Promise(resolve => { resolveOpen = resolve }),
      },
      global: { plugins: [router] },
    })

    const chooser = wrapper.get('[aria-label="Choose project folder"]')
    await chooser.trigger('click')
    expect(chooser.attributes('disabled')).toBeDefined()

    resolveOpen?.(null)
    await flushPromises()
    expect(chooser.attributes('disabled')).toBeUndefined()
  })

  it('routes to the opened canonical workspace after protected local import', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    const wrapper = mount(OpenProjectPage, {
      props: {
        openProject: async () => {
          expect(selection.reference).toHaveLength(64)
          return {
            projectId: '01890e00-0000-7000-8000-000000000001',
            workspaceId: '01890e00-0000-7000-8000-000000000002',
          }
        },
      },
      global: { plugins: [router] },
    })

    await wrapper.get('[aria-label="Choose project folder"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/workspaces/01890e00-0000-7000-8000-000000000002')
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
