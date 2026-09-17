import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'
import ProjectsPage from './ProjectsPage.vue'

describe('projects start page', () => {
  it('offers one folder action without duplicating the sidebar project list', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/', component: ProjectsPage },
      { path: '/projects/open', name: 'open-project', component: { template: '<div />' } },
    ] })
    await router.push('/')
    const wrapper = mount(ProjectsPage, { global: { plugins: [router] } })
    expect(wrapper.findAll('button')).toHaveLength(1)
    expect(wrapper.find('ul').exists()).toBe(false)
    expect(wrapper.text()).toContain('sidebar')
    await wrapper.get('button').trigger('click')
    await router.isReady()
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(router.currentRoute.value.name).toBe('open-project')
  })
})
