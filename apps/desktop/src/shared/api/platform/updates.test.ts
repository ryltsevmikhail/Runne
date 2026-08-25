import { describe, expect, it } from 'vitest'

import { checkUpdate, getUpdateStatus, prepareUpdateInstall } from './updates'

describe('getUpdateStatus', () => {
  it('accepts explicit unavailable owner state', async () => {
    await expect(getUpdateStatus(async () => ({
      state: 'unavailable',
      currentVersion: '0.1.0',
      availableVersion: null,
      artifactSha256: null,
      reason: 'metadata_source_unavailable',
    }))).resolves.toMatchObject({ state: 'unavailable' })
  })

  it('rejects unknown fields and malformed artifact digests', async () => {
    await expect(getUpdateStatus(async () => ({
      state: 'available',
      currentVersion: '0.1.0',
      availableVersion: '0.2.0',
      artifactSha256: 'secret',
      reason: null,
      token: 'forbidden',
    }))).rejects.toThrow()
  })

  it('sends only native update commands and confirmation intent', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    const invoke = async (command: string, args?: Record<string, unknown>) => {
      calls.push([command, args])
      return {
        state: 'available',
        currentVersion: '0.1.0',
        availableVersion: '0.2.0',
        artifactSha256: 'a'.repeat(64),
        reason: null,
      }
    }
    await checkUpdate(invoke)
    await prepareUpdateInstall(true, invoke)
    expect(calls).toEqual([
      ['check_update', undefined],
      ['prepare_update_install', { confirmActiveTaskRuns: true }],
    ])
  })
})
