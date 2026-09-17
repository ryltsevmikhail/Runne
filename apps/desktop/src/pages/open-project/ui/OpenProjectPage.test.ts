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
  it('renders a compact native folder chooser without a duplicate privacy notice', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    const wrapper = mount(OpenProjectPage, {
      props: { openProject: async () => null },
      global: { plugins: [router] },
    })

    expect(wrapper.find('.open-project-page').exists()).toBe(true)
    expect(wrapper.get('[aria-label="Choose project folder"]').classes()).toContain('gc-button')
    expect(wrapper.findAll('[aria-label="Choose project folder"] svg')).toHaveLength(1)
    expect(wrapper.find('.open-project-page__privacy').exists()).toBe(false)
    expect(wrapper.find('.open-project-page__choose-card').exists()).toBe(false)
    expect(wrapper.find('.eyebrow').exists()).toBe(false)
    expect(wrapper.html()).not.toContain('IMPLEMENTED')
  })

  it('keeps the title and folder chooser in one centered content shell', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    const wrapper = mount(OpenProjectPage, {
      props: { openProject: async () => null },
      global: { plugins: [router] },
    })

    const content = wrapper.get('.open-project-page__content')
    expect(content.get('#open-project-title').text()).toBe('Open a project')
    expect(content.get('[aria-label="Choose project folder"]').attributes('type')).toBe('button')
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

  it('does not hijack a later route when the folder import resolves after navigation', async () => {
    const router = createTestRouter()
    await router.push('/projects/open')
    await router.isReady()
    let resolveOpen: ((result: { projectId: string; workspaceId: string }) => void) | undefined
    const wrapper = mount(OpenProjectPage, {
      props: {
        openProject: () => new Promise(resolve => { resolveOpen = resolve }),
      },
      global: { plugins: [router] },
    })

    await wrapper.get('[aria-label="Choose project folder"]').trigger('click')
    await flushPromises()
    await router.push({ name: 'project-details', params: { projectId: '01890e00-0000-7000-8000-000000000001' } })
    resolveOpen?.({
      projectId: '01890e00-0000-7000-8000-000000000001',
      workspaceId: '01890e00-0000-7000-8000-000000000002',
    })
    await flushPromises()

    expect(router.currentRoute.value.fullPath).toBe('/projects/01890e00-0000-7000-8000-000000000001')
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
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
