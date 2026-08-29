import { describe, expect, it } from 'vitest'

import { routes } from './router'

describe('desktop routes', () => {
  it('keeps Project and Workspace route parameters distinct', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('project-details')).toBe('/projects/:projectId')
    expect(paths.get('workspace')).toBe('/workspaces/:workspaceId')
  })

  it('exposes a TaskRun route using only the canonical runtime ID', () => {
    const taskRun = routes.find(route => route.name === 'task-run')

    expect(taskRun?.path).toBe('/task-runs/:taskRunId')
  })

  it('keeps the TaskRun inventory separate from the detail route', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('task-run-inventory')).toBe('/task-runs')
    expect(paths.get('task-run')).toBe('/task-runs/:taskRunId')
  })

  it('exposes the owner-bound appearance settings route', () => {
    const appearance = routes.find(route => route.name === 'appearance-settings')

    expect(appearance?.path).toBe('/settings/appearance')
  })

  it('exposes isolated settings routes for local desktop preferences', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('settings')).toBe('/settings')
    expect(paths.get('shortcuts-settings')).toBe('/settings/shortcuts')
    expect(paths.get('providers-settings')).toBe('/settings/providers')
    expect(paths.get('devices-settings')).toBe('/settings/devices')
    expect(paths.get('updates-settings')).toBe('/settings/updates')
  })
})
