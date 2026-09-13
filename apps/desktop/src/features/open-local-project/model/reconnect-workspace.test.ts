import { describe, expect, it, vi } from 'vitest'
import {
  LocalProjectOpenError,
  RetryableWorkspaceOpen,
  selectAndOpenExistingWorkspace,
} from './open-local-project'

describe('reconnect existing workspace', () => {
  it('retains the exact native attempt across a lost acknowledgement', async () => {
    const select = vi.fn(async () => ({ reference: 'a'.repeat(64) }))
    const prepare = vi.fn(async () => ({ reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' as const } }))
    const open = vi.fn(async () => { throw { code: 'prepared_workspace_retryable' } })
    const retry = vi.fn(async () => {})
    try {
      await selectAndOpenExistingWorkspace('workspace', 2, async () => 7, select, prepare, open, retry)
      expect.unreachable()
    }
    catch (error) {
      expect(error).toBeInstanceOf(RetryableWorkspaceOpen)
      await (error as RetryableWorkspaceOpen).retry()
    }
    expect(select).toHaveBeenCalledTimes(1)
    expect(prepare).toHaveBeenCalledTimes(1)
    expect(open).toHaveBeenCalledTimes(1)
    expect(retry.mock.calls[0]).toEqual(open.mock.calls[0])
  })

  it('keeps the workspace identity and native selection binding through prepare and open', async () => {
    const select = vi.fn(async () => ({ reference: 'a'.repeat(64) }))
    const prepare = vi.fn(async () => ({ reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' as const } }))
    const open = vi.fn(async () => {})
    await selectAndOpenExistingWorkspace('workspace', 2, async () => 7, select, prepare, open)
    const [requestId, rendererGeneration] = select.mock.calls[0] as unknown as [string, number]
    expect(prepare).toHaveBeenCalledWith({
      workspaceId: 'workspace', expectedVersion: 2, selection: 'a'.repeat(64),
      requestId, rendererGeneration,
    })
    expect(open).toHaveBeenCalledWith({ prepared: 'b'.repeat(64), requestId, rendererGeneration })
  })

  it('exposes one immutable binding for the retained native attempt', async () => {
    const select = vi.fn(async () => ({ reference: 'a'.repeat(64) }))
    const prepare = vi.fn(async () => ({
      reference: 'b'.repeat(64),
      summary: { displayName: 'Selected folder' as const },
    }))
    const open = vi.fn(async () => { throw { code: 'prepared_workspace_retryable' } })

    await expect(
      selectAndOpenExistingWorkspace('workspace', 2, async () => 7, select, prepare, open),
    ).rejects.toMatchObject({
      binding: {
        workspaceId: 'workspace',
        prepared: 'b'.repeat(64),
        requestId: expect.any(String),
        rendererGeneration: 7,
      },
    })
  })

  it('keeps the same binding through retryable to retryable to success', async () => {
    const select = vi.fn(async () => ({ reference: 'a'.repeat(64) }))
    const prepare = vi.fn(async () => ({
      reference: 'b'.repeat(64),
      summary: { displayName: 'Selected folder' as const },
    }))
    const open = vi.fn(async () => { throw { code: 'prepared_workspace_retryable' } })
    const retry = vi.fn()
      .mockRejectedValueOnce({ code: 'prepared_workspace_retryable' })
      .mockResolvedValueOnce(undefined)

    let first!: RetryableWorkspaceOpen
    try {
      await selectAndOpenExistingWorkspace('workspace', 2, async () => 7, select, prepare, open, retry)
    }
    catch (error) {
      first = error as RetryableWorkspaceOpen
    }

    const second = await first.retry().catch(error => error as RetryableWorkspaceOpen) as RetryableWorkspaceOpen
    await second.retry()

    expect(second.binding).toEqual(first.binding)
    expect(select).toHaveBeenCalledTimes(1)
    expect(prepare).toHaveBeenCalledTimes(1)
    expect(retry).toHaveBeenCalledTimes(2)
    expect(retry.mock.calls[0]).toEqual(retry.mock.calls[1])
  })

  it('rebuilds retry arguments from the original binding after dispatch mutation', async () => {
    const select = vi.fn(async () => ({ reference: 'a'.repeat(64) }))
    const prepare = vi.fn(async () => ({
      reference: 'b'.repeat(64),
      summary: { displayName: 'Selected folder' as const },
    }))
    const open = vi.fn(async request => {
      Object.assign(request, {
        prepared: 'c'.repeat(64),
        requestId: 'mutated-request',
        rendererGeneration: 99,
      })
      throw { code: 'prepared_workspace_retryable' }
    })
    const retry = vi.fn(async () => {})

    let error!: RetryableWorkspaceOpen
    try {
      await selectAndOpenExistingWorkspace('workspace', 2, async () => 7, select, prepare, open, retry)
      expect.unreachable()
    }
    catch (caught) {
      error = caught as RetryableWorkspaceOpen
    }

    await error.retry()

    expect(error.binding).toMatchObject({
      workspaceId: 'workspace',
      prepared: 'b'.repeat(64),
      requestId: expect.any(String),
      rendererGeneration: 7,
    })
    expect(retry).toHaveBeenCalledWith({
      prepared: 'b'.repeat(64),
      requestId: error.binding.requestId,
      rendererGeneration: 7,
    })
  })

  it('keeps the prepared identity when its result alias is mutated during dispatch', async () => {
    const prepared = {
      reference: 'b'.repeat(64),
      summary: { displayName: 'Selected folder' as const },
    }
    const prepare = vi.fn(async () => prepared)
    const open = vi.fn(async () => {
      prepared.reference = 'c'.repeat(64)
      throw { code: 'prepared_workspace_retryable' }
    })
    const retry = vi.fn(async () => {})

    let error!: RetryableWorkspaceOpen
    try {
      await selectAndOpenExistingWorkspace('workspace', 2, async () => 7,
        async () => ({ reference: 'a'.repeat(64) }), prepare, open, retry)
      expect.unreachable()
    }
    catch (caught) {
      error = caught as RetryableWorkspaceOpen
    }

    await error.retry()

    expect(error.binding.prepared).toBe('b'.repeat(64))
    expect(retry).toHaveBeenCalledWith({
      prepared: 'b'.repeat(64),
      requestId: error.binding.requestId,
      rendererGeneration: 7,
    })
  })

  it('does not continue for a non-exact initial retryable code', async () => {
    const open = vi.fn(async () => { throw { code: 'prepared_workspace_retryable_extra' } })

    await expect(selectAndOpenExistingWorkspace('workspace', 2, async () => 7,
      async () => ({ reference: 'a'.repeat(64) }),
      async () => ({ reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' as const } }),
      open,
    )).rejects.toBeInstanceOf(LocalProjectOpenError)
  })

  it('stops after the first retry when its failure code is not exact', async () => {
    const open = vi.fn(async () => { throw { code: 'prepared_workspace_retryable' } })
    const retry = vi.fn(async () => { throw { code: 'prepared_workspace_retryable_extra' } })
    let error!: RetryableWorkspaceOpen

    try {
      await selectAndOpenExistingWorkspace('workspace', 2, async () => 7,
        async () => ({ reference: 'a'.repeat(64) }),
        async () => ({ reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' as const } }),
        open, retry,
      )
      expect.unreachable()
    }
    catch (caught) {
      error = caught as RetryableWorkspaceOpen
    }

    await expect(error.retry()).rejects.toBeInstanceOf(LocalProjectOpenError)
    expect(retry).toHaveBeenCalledTimes(1)
  })

  it('does not prepare or open after cancellation', async () => {
    const prepare = vi.fn()
    const open = vi.fn()
    expect(await selectAndOpenExistingWorkspace('workspace', 2, async () => 7,
      async () => null, prepare, open)).toBeNull()
    expect(prepare).not.toHaveBeenCalled()
    expect(open).not.toHaveBeenCalled()
  })

  it('does not dispatch after a rejected admission and redacts native details', async () => {
    const open = vi.fn()
    await expect(selectAndOpenExistingWorkspace('workspace', 2, async () => 7,
      async () => ({ reference: 'a'.repeat(64) }),
      async () => { throw new Error('/private/owner/path') }, open,
    )).rejects.toMatchObject({ stage: 'workspace', message: 'Local project could not be opened' })
    expect(open).not.toHaveBeenCalled()
  })
})
