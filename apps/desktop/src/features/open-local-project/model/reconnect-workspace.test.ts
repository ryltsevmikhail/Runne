import { describe, expect, it, vi } from 'vitest'
import { RetryableWorkspaceOpen, selectAndOpenExistingWorkspace } from './open-local-project'

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
