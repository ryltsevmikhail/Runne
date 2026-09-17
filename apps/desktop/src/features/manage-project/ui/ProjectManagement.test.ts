import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const native = vi.hoisted(() => ({
  invoke: vi.fn(),
  isTauri: vi.fn(() => false),
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: native.invoke,
  isTauri: native.isTauri,
}))

import type { CanonicalProject } from '@/entities/project'
import ProjectManagement from './ProjectManagement.vue'

const project: CanonicalProject = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  displayName: 'runne',
  version: 1,
  archived: false,
}

const workspace = {
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  projectId: project.projectId,
  displayName: 'editor',
  version: 1,
  open: false,
}

describe('ProjectManagement', () => {
  beforeEach(() => {
    native.invoke.mockReset()
    native.isTauri.mockReturnValue(false)
  })

  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('requires an explicit compact confirmation before deleting a project in the browser shell', async () => {
    const removed = vi.fn()
    native.invoke.mockImplementation(async (command: string) => {
      if (command === 'get_canonical_project') return { project, workspaces: [workspace] }
      if (command === 'acquire_renderer_generation') return 8
      if (command === 'prepare_destructive_project_action') return 'a'.repeat(64)
      if (command === 'dispatch_destructive_project_action') return undefined
      throw new Error(`unexpected command: ${command}`)
    })
    const wrapper = mount(ProjectManagement, {
      attachTo: document.body,
      props: { project, disabled: false },
      attrs: { onRemoved: removed },
    })

    const trigger = wrapper.get('[aria-label="Manage project"]')
    await trigger.trigger('click')
    const menu = wrapper.get('[role="menu"]')
    const actionButtons = menu.findAll('button')
    expect(actionButtons).toHaveLength(3)
    expect(actionButtons.every(button => button.attributes('role') === 'menuitem')).toBe(true)
    expect(trigger.attributes('aria-haspopup')).toBe('menu')
    await wrapper.get('[aria-label="Delete project"]').trigger('click')
    await flushPromises()

    expect(document.body.querySelector('[role="dialog"]')?.textContent).toContain('runne')
    expect(native.invoke).not.toHaveBeenCalled()

    document.body.querySelector<HTMLButtonElement>('.gc-dialog-btn--cancel')?.click()
    await flushPromises()
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    expect(native.invoke).not.toHaveBeenCalled()

    await wrapper.get('[aria-label="Manage project"]').trigger('click')
    await wrapper.get('[aria-label="Delete project"]').trigger('click')
    document.body.querySelector<HTMLButtonElement>('.gc-dialog-btn:not(.gc-dialog-btn--cancel)')?.click()
    await flushPromises()

    expect(native.invoke.mock.calls.map(([command]) => command)).toEqual([
      'get_canonical_project',
      'acquire_renderer_generation',
      'prepare_destructive_project_action',
      'dispatch_destructive_project_action',
    ])
    expect(removed).toHaveBeenCalledOnce()
  })
})
