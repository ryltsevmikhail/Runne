import { describe, expect, it } from 'vitest'

import { routes } from './router'

describe('desktop routes', () => {
  it('keeps Project and Workspace route parameters distinct', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('project-details')).toBe('/projects/:projectId')
    expect(paths.get('workspace')).toBe('/workspaces/:workspaceId')
  })
})
