import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcButton from './gc-button/GcButton.vue'
import GcInput from './gc-input/GcInput.vue'
import GcBadge from './gc-badge/GcBadge.vue'
import GcAlert from './gc-alert/GcAlert.vue'
import GcProjectCard from './gc-project-card/GcProjectCard.vue'
import GcWorkspacePanel from './gc-workspace-panel/GcWorkspacePanel.vue'

describe('Component library integration', () => {
  it('renders all components together without conflicts', () => {
    const wrapper = mount({
      components: { GcButton, GcInput, GcBadge, GcAlert, GcProjectCard, GcWorkspacePanel },
      template: `
        <div>
          <GcButton>Action</GcButton>
          <GcInput :modelValue="'text'" />
          <GcBadge status="ready">Ready</GcBadge>
          <GcAlert level="info" title="Info">Message</GcAlert>
          <GcProjectCard :project="{ name:'Test', path:'/test', slug:'t', status:'ready', modifiedAt:'now' }" />
          <GcWorkspacePanel :tabs="[{id:'a',label:'Tab A'}]" activeTab="a" panelState="empty" />
        </div>
      `,
    })
    expect(wrapper.find('.gc-button').exists()).toBe(true)
    expect(wrapper.find('.gc-input').exists()).toBe(true)
    expect(wrapper.find('.gc-badge').exists()).toBe(true)
    expect(wrapper.find('.gc-alert').exists()).toBe(true)
    expect(wrapper.find('.gc-project-card').exists()).toBe(true)
  })

  it('barrel exports all components', async () => {
    const barrel = await import('./index')
    expect(Object.keys(barrel)).toContain('GcButton')
    expect(Object.keys(barrel)).toContain('GcInput')
    expect(Object.keys(barrel)).toContain('GcTextarea')
    expect(Object.keys(barrel)).toContain('GcBadge')
    expect(Object.keys(barrel)).toContain('GcAlert')
    expect(Object.keys(barrel)).toContain('GcSidebar')
    expect(Object.keys(barrel)).toContain('GcTitleBar')
    expect(Object.keys(barrel)).toContain('GcProjectCard')
    expect(Object.keys(barrel)).toContain('GcDialog')
    expect(Object.keys(barrel)).toContain('GcCommandPalette')
    expect(Object.keys(barrel)).toContain('GcWorkspacePanel')
    expect(Object.keys(barrel)).toContain('GcRecoveryState')
  })
})
