import { describe, expect, it, vi } from 'vitest'

import { LocalModelManager } from './local-model-manager'

const admittedModel = {
  manifestDigest: 'a'.repeat(64),
  modelId: 'acme.tiny',
  modelRevision: '2026.09.08',
  matrixRevision: 'matrix-v1',
  activeRefs: 0,
} as const

describe('local model manager', () => {
  it('keeps the admitted model in its installed-model cache', async () => {
    const invoke = vi.fn(async (command: string) => {
      if (command === 'local_model_admit') return admittedModel
      throw new Error(`Unexpected command: ${command}`)
    })
    const manager = new LocalModelManager(invoke)

    await expect(manager.admit('candidate-1', 'license-digest')).resolves.toEqual(admittedModel)
    expect(manager.installedModels()).toEqual([admittedModel])
  })
})
