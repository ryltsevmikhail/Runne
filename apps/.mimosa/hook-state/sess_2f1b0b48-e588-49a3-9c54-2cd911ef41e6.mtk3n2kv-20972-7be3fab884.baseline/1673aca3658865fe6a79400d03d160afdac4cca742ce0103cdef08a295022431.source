import { describe, expect, it } from 'vitest'

import { exportDiagnostics, getDiagnosticsExportPreview } from './diagnostics-export'

describe('diagnostics export IPC adapter', () => {
  it('accepts only the bounded preview and closed export result', async () => {
    await expect(getDiagnosticsExportPreview(async () => ({
      schemaVersion: 1,
      redactionVersion: 1,
      categories: ['application', 'runtime'],
      estimatedBytes: 512,
    }))).resolves.toMatchObject({ estimatedBytes: 512 })
    await expect(getDiagnosticsExportPreview(async () => ({
      schemaVersion: 2,
      redactionVersion: 1,
      categories: ['application'],
      estimatedBytes: 512,
    }))).rejects.toThrow('Invalid diagnostics export preview')

    await expect(exportDiagnostics(async () => ({ status: 'saved' }))).resolves.toEqual({ status: 'saved' })
    await expect(exportDiagnostics(async () => ({ status: 'written', path: '/private' }))).rejects.toThrow(
      'Invalid diagnostics export result',
    )
  })
})
