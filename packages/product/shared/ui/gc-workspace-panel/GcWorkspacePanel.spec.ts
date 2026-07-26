import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcWorkspacePanel from './GcWorkspacePanel.vue'

describe('GcWorkspacePanel', () => {
  const defaultProps = {
    tabs: [
      { id: 'tab1', label: 'Tab One' },
      { id: 'tab2', label: 'Tab Two', badge: 3 },
    ],
    activeTab: 'tab1',
    panelState: 'empty' as const,
  }

  it('renders tabs', () => {
    const wrapper = mount(GcWorkspacePanel, { props: defaultProps })
    const tabButtons = wrapper.findAll('.gc-workspace-panel-tab')
    expect(tabButtons).toHaveLength(2)
    expect(tabButtons[0].text()).toContain('Tab One')
    expect(tabButtons[1].text()).toContain('Tab Two')
    expect(tabButtons[1].text()).toContain('3')
  })

  it('emits selectTab when a tab is clicked', async () => {
    const wrapper = mount(GcWorkspacePanel, { props: defaultProps })
    const tabButtons = wrapper.findAll('.gc-workspace-panel-tab')
    await tabButtons[1].trigger('click')
    expect(wrapper.emitted('selectTab')).toBeTruthy()
    expect(wrapper.emitted('selectTab')![0]).toEqual(['tab2'])
  })

  it('shows empty state when panelState is empty', () => {
    const wrapper = mount(GcWorkspacePanel, { props: defaultProps })
    expect(wrapper.find('.gc-workspace-panel-empty').exists()).toBe(true)
    expect(wrapper.text()).toContain('Nothing here yet')
    expect(wrapper.text()).toContain('Open a file to get started')
  })

  it('shows loading skeletons when panelState is loading', () => {
    const wrapper = mount(GcWorkspacePanel, {
      props: { ...defaultProps, panelState: 'loading' },
    })
    expect(wrapper.find('.gc-workspace-panel-loading').exists()).toBe(true)
    const skeletons = wrapper.findAll('.gc-workspace-panel-skeleton')
    expect(skeletons).toHaveLength(3)
  })

  it('shows unavailable state with retry button when panelState is unavailable', () => {
    const wrapper = mount(GcWorkspacePanel, {
      props: { ...defaultProps, panelState: 'unavailable' },
    })
    expect(wrapper.find('.gc-workspace-panel-unavailable').exists()).toBe(true)
    expect(wrapper.text()).toContain('Panel unavailable')
    const retryBtn = wrapper.find('.gc-workspace-panel-retry-btn')
    expect(retryBtn.exists()).toBe(true)
    expect(retryBtn.text()).toBe('Retry')
  })
})
