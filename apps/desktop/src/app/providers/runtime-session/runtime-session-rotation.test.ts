import { describe, expect, it, vi } from 'vitest'

import { createRuntimeSessionController } from './runtime-session'

const bootstrap = (runtime: unknown) => ({
  theme: 'dark',
  runtimeMode: 'external_local',
  runtime,
  runtimeLifecycle: 'external',
  runtimeFailure: null,
})

const transientReject = (message: string): Error => {
  const error: Error & { disposition?: string } = new Error(message)
  error.disposition = 'transient'
  return error
}

describe('runtime session rotation windows', () => {
  it('recovers automatically after transport-level establishment failures', async () => {
    let connects = 0
    let failConnect = false
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (failConnect && connects > 1) throw transientReject('transport closed')
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // A rotation window: transient projection, then recovery attempts whose
    // connect throws. Transport exceptions must not latch terminal state.
    failConnect = true
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(2))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(3))

    // Once the daemon is healthy again the next observation self-heals.
    failConnect = false
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('publishes unavailable for a failed transient manual connect and keeps recovery armed', async () => {
    let failConnect = true
    const port = createRuntimeSessionController({
      connect: async () => {
        if (failConnect) throw transientReject('transport closed')
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })

    failConnect = false
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('still latches terminal establishment outcomes during rotation windows', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return connects === 2 ? 'revoked' : 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(2))
    for (let observation = 0; observation < 4; observation += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
    }
    expect(connects).toBe(2)
    expect(port.snapshot().canMutate).toBe(false)
  })

  it('latches a terminal typed reject until a manual retry', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        throw Object.assign(new Error('session revoked'), { disposition: 'terminal' })
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
    for (let observation = 0; observation < 5; observation += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    }
    expect(connects).toBe(1)
    expect(port.snapshot().canMutate).toBe(false)

    await port.retry()
    expect(connects).toBe(2)
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
  })

  it('latches an untyped malformed reject as terminal', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        throw new Error('malformed payload')
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(1)
    expect(port.snapshot().canMutate).toBe(false)

    await port.retry()
    expect(connects).toBe(2)
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
  })

  it('keeps a terminal connect verdict when bootstrap rejects afterwards', async () => {
    // Automatic path: a live session enters a rotation window, the recovery
    // connect returns a terminal verdict and bootstrap throws — the verdict
    // must latch and block further automatic connects until a manual retry.
    let connects = 0
    let failingBootstrap = false
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return connects === 1 ? 'live' : 'revoked'
      },
      loadBootstrap: async () => {
        if (failingBootstrap) throw new Error('bootstrap transport')
        return bootstrap('live')
      },
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    failingBootstrap = true
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(2))
    failingBootstrap = false
    for (let observation = 0; observation < 4; observation += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
    }
    expect(connects).toBe(2)
    expect(port.snapshot().canMutate).toBe(false)
    await port.retry()
    expect(connects).toBe(3)
    expect(port.snapshot().canMutate).toBe(false)
  })

  it('keeps a terminal connect verdict when a manual attempt hits a bootstrap exception', async () => {
    let connects = 0
    let failingBootstrap = true
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return 'revoked'
      },
      loadBootstrap: async () => {
        if (failingBootstrap) throw new Error('bootstrap transport')
        return bootstrap('live')
      },
    })

    await port.connect()
    failingBootstrap = false
    for (let observation = 0; observation < 4; observation += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
    }
    expect(port.snapshot().canMutate).toBe(false)
    const observed = connects
    await port.retry()
    expect(connects).toBe(observed + 1)
    expect(port.snapshot().canMutate).toBe(false)
  })

  it('keeps the pre-recovery projection during an automatic attempt', async () => {
    let releaseConnect: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: () => {
        connects += 1
        if (connects === 2) {
          return new Promise(resolve => {
            releaseConnect = resolve
          })
        }
        return Promise.resolve('live')
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(2))
    // An automatic attempt must not overwrite the observation projection.
    expect(port.snapshot()).toMatchObject({ status: 'stale', canMutate: false })
    releaseConnect?.('live')
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('starts bounded recovery immediately on a transient observation', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (connects === 2) return new Promise(() => {})
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    // The transient projection itself triggers the single-flight recovery.
    await vi.waitFor(() => expect(connects).toBe(2))
    expect(port.snapshot()).toMatchObject({ status: 'reconnecting', canMutate: false })
  })

  it('a failed manual transport retry re-arms the automatic budget', async () => {
    let connects = 0
    let failConnect = false
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (failConnect) throw transientReject('transport down')
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    // Burn the automatic budget with three transport failures.
    failConnect = true
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(2))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(3))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(connects).toBe(4))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(4)

    // A failed manual retry re-arms the budget...
    await port.retry()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })

    // ...and the recovered transport lets automatic recovery prove live.
    failConnect = false
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })
})
