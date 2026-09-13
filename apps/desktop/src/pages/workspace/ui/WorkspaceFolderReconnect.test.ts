import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WorkspaceFolderReconnect from './WorkspaceFolderReconnect.vue'
import { RetryableWorkspaceOpen } from '@/features/open-local-project'

const api = vi.hoisted(() => ({ load: vi.fn(), connect: vi.fn() }))
vi.mock('@/entities/project', () => ({ getCanonicalWorkspace: api.load }))
vi.mock('@/features/open-local-project', async importOriginal => ({
  ...await importOriginal<typeof import('@/features/open-local-project')>(),
  selectAndOpenExistingWorkspace: api.connect,
}))

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

describe('workspace folder reconnect', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    api.load.mockResolvedValue({ workspaceId: 'existing', version: 9 })
    api.connect.mockResolvedValue({ reference: 'opaque' })
  })
  const render = (pending: RetryableWorkspaceOpen | null = null) => mount(WorkspaceFolderReconnect, {
    props: { workspaceId: 'existing', viewGeneration: 3, disabled: false, pending },
  })

  it('reads the current version and refreshes only after native completion', async () => {
    const wrapper = render()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(api.connect).toHaveBeenCalledWith('existing', 9)
    expect(wrapper.emitted('connected')).toEqual([['existing', 3]])
  })

  it('does not report a cancelled picker as completion or failure', async () => {
    api.connect.mockResolvedValue(null)
    const wrapper = render()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.emitted('connected')).toBeUndefined()
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('retries a retained native attempt instead of starting another picker', async () => {
    const retry = vi.fn(async () => ({ reference: 'opaque', summary: { displayName: 'Selected folder' as const } }))
    const error = new RetryableWorkspaceOpen({
      workspaceId: 'existing', prepared: 'b'.repeat(64), requestId: 'request-1', rendererGeneration: 7,
    }, retry)
    api.connect.mockRejectedValue(error)
    const wrapper = render()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.emitted('retryable')?.[0]).toEqual([error, 'existing', 3])
    await wrapper.setProps({ pending: error })
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(retry).toHaveBeenCalledTimes(1)
    expect(api.load).toHaveBeenCalledTimes(1)
    expect(api.connect).toHaveBeenCalledTimes(1)
    expect(wrapper.emitted('connected')).toEqual([['existing', 3]])
  })

  it('retains the same retry binding when disabled before a retryable rejection', async () => {
    const native = deferred<never>()
    const retry = vi.fn(async () => ({ reference: 'opaque', summary: { displayName: 'Selected folder' as const } }))
    const error = new RetryableWorkspaceOpen({
      workspaceId: 'existing', prepared: 'b'.repeat(64), requestId: 'request-1', rendererGeneration: 7,
    }, retry)
    api.connect.mockReturnValue(native.promise)
    const wrapper = render()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    await wrapper.setProps({ disabled: true })
    native.reject(error)
    await flushPromises()
    expect(wrapper.emitted('retryable')).toEqual([[error, 'existing', 3]])
    expect(wrapper.emitted('connected')).toBeUndefined()
    await wrapper.setProps({ disabled: false, pending: error })
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(retry).toHaveBeenCalledTimes(1)
    expect(api.load).toHaveBeenCalledTimes(1)
    expect(api.connect).toHaveBeenCalledTimes(1)
    expect(wrapper.emitted('connected')).toEqual([['existing', 3]])
  })

  it('shows a safe failure and permits another attempt', async () => {
    api.connect.mockRejectedValue(new Error('/private/owner/path'))
    const wrapper = render()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('/private/')
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
    expect(wrapper.emitted('failed')).toEqual([['existing', 3]])
  })

  it('does not start native work after navigation during snapshot loading', async () => {
    let resolve!: (value: { version: number }) => void
    api.load.mockReturnValue(new Promise(value => { resolve = value }))
    const wrapper = render()
    await wrapper.get('button').trigger('click')
    await wrapper.setProps({ viewGeneration: 4 })
    resolve({ version: 9 })
    await flushPromises()
    expect(api.connect).not.toHaveBeenCalled()
    expect(wrapper.emitted('connected')).toBeUndefined()
    expect(wrapper.emitted('retryable')).toBeUndefined()
    expect(wrapper.emitted('failed')).toBeUndefined()
  })
})
