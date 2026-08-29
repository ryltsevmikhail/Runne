import { describe, expect, it } from 'vitest'

import { routes } from './router'

describe('desktop routes', () => {
  it('keeps Project and Workspace route parameters distinct', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('project-details')).toBe('/projects/:projectId')
    expect(paths.get('workspace')).toBe('/workspaces/:workspaceId')
  })

  it('provides stable deep links for every primary sidebar destination', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('projects')).toBe('/')
    expect(paths.get('task-runs')).toBe('/task-runs')
    expect(paths.get('diagnostics')).toBe('/diagnostics')
    expect(paths.get('runtime-settings')).toBe('/settings/runtimes')
  })
})
