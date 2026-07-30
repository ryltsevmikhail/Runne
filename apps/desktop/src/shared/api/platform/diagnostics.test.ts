import { describe, expect, it } from 'vitest'

import { getDiagnostics } from './diagnostics'

describe('diagnostics platform API', () => {
  it('accepts the exact bounded diagnostics contract', async () => {
    const snapshot = await getDiagnostics(async () => ({
      appVersion: '0.1.0',
      platform: 'macos',
      databaseSchemaVersion: 3,
      databaseGeneration: 4,
      projectCount: 2,
      runtimeMode: 'external_local',
      runtime: 'unconfigured',
      runtimeLifecycle: 'external',
      runtimeFailure: null,
    }))

    expect(snapshot.databaseGeneration).toBe(4)
  })

  it('rejects responses with undeclared fields', async () => {
    await expect(getDiagnostics(async () => ({
      appVersion: '0.1.0',
      platform: 'macos',
      databaseSchemaVersion: 3,
      databaseGeneration: 4,
      projectCount: 2,
      runtimeMode: 'external_local',
      runtime: 'unconfigured',
      runtimeLifecycle: 'external',
      runtimeFailure: null,
      projectPath: '/private/project',
    }))).rejects.toThrow('Invalid diagnostics response')
  })
})
