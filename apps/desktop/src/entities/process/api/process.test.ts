import { describe, expect, it } from 'vitest'

import { readProcessOutput, startProcess } from './process'

const ID = '018f2e3a-7000-7000-8000-000000000401'

describe('process API', () => {
  it('validates and decodes an authenticated start snapshot', async () => {
    const value = await startProcess(ID, ID, ID, ID, async (command, args) => {
      expect(command).toBe('start_process')
      expect(args).toEqual({ workspaceId: ID, taskRunId: ID, attemptId: ID, invocationId: ID })
      return { processId: ID, invocationId: ID, workspaceId: ID, state: 'running', version: 1, nextOutputSequence: 1 }
    })
    expect(value.state).toBe('running')
  })

  it('rejects control and bidi output', async () => {
    await expect(readProcessOutput(ID, 0, 2, async () => ({
      chunks: [{ sequence: 1, stream: 'stdout', text: 'bad\u{009b}' }],
    }))).rejects.toThrow('Invalid process output')
  })
})
