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

describe('runtime session revocation and concurrent manual races', () => {
  it('drops a manual attempt when a revocation arrives during its connect', async () => {
    let releaseStaleConnect: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: () => {
        connects += 1
        if (connects === 2) {
          return new Promise(resolve => {
            releaseStaleConnect = resolve
          })
        }
        return Promise.resolve('live')
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))

    // The manual attempt starts its connect; a revocation arrives meanwhile and
    // must keep the session read-only once the stale connect resolves.
    const retrying = port.retry()
    port.observeBootstrap(bootstrap('revoked'))
    releaseStaleConnect?.('live')
    await retrying
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(2)
    expect(port.snapshot()).toMatchObject({ status: 'revoked', canMutate: false })
  })

  it('keeps the newer concurrent manual result authoritative and blocks recovery', async () => {
    let releaseOlder: ((value: unknown) => void) | undefined
    let releaseNewer: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: () => {
        connects += 1
        if (connects === 2) {
          return new Promise(resolve => {
            releaseOlder = resolve
          })
        }
        if (connects === 3) {
          return new Promise(resolve => {
            releaseNewer = resolve
          })
        }
        return Promise.resolve('live')
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    const older = port.retry()
    const newer = port.retry()
    expect(connects).toBe(3)

    // The older manual completes first with a non-live proof: the still-running
    // newer manual must keep automatic recovery blocked.
    releaseOlder?.('reconnecting')
    await older
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(3)

    releaseNewer?.('live')
    await newer
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // With no manual in flight the bounded recovery may run again.
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(4)
  })

  it('cancels a queued recovery when a revocation arrives before its microtask', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    port.observeBootstrap(bootstrap('revoked'))
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(1)
    expect(port.snapshot()).toMatchObject({ status: 'revoked', canMutate: false })
  })

  it('lets recovery run after a hung older manual once a newer manual succeeds', async () => {
    let releaseHung: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: () => {
        connects += 1
        if (connects === 2) {
          return new Promise(resolve => {
            releaseHung = resolve
          })
        }
        return Promise.resolve('live')
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    const hung = port.retry()
    await port.retry()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // The hung older manual must not block automatic recovery any more.
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(4)
    releaseHung?.('live')
    await hung
  })

  it('never auto-recovers from terminal or resync conditions', async () => {
    for (const terminal of ['revoked', 'resync_required', 'fatal', 'incompatible']) {
      let connects = 0
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      port.observeBootstrap(bootstrap(terminal))
      for (let observation = 0; observation < 5; observation += 1) {
        port.observeBootstrap(bootstrap('live'))
        await Promise.resolve()
        await Promise.resolve()
        await Promise.resolve()
      }
      expect(connects).toBe(1)
      expect(port.snapshot().canMutate).toBe(false)

      // An explicit manual action still recovers the session.
      await port.retry()
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    }
  })

  it('keeps an in-flight recovery alive across its own transient projection', async () => {
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
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(2)

    // The recovery's own backend projection must not discard it.
    port.observeBootstrap(bootstrap('reconnecting'))
    releaseConnect?.('live')
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    expect(connects).toBe(2)
  })

  it('spends no recovery budget on schedules cancelled before they start', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return 'reconnecting'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    for (let cycle = 0; cycle < 3; cycle += 1) {
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      port.observeBootstrap(bootstrap('revoked'))
    }
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(1)

    // A revocation latches: only a manual retry re-arms recovery, and the
    // budget is intact — three real attempts are still allowed.
    await port.retry()
    expect(connects).toBe(2)
    port.observeBootstrap(bootstrap('reconnecting'))
    for (let attempt = 0; attempt < 6; attempt += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    }
    await vi.waitFor(() => {
      expect(connects).toBe(2 + 3)
    })
  })

  it('blocks automatic recovery after terminal establishment outcomes', async () => {
    for (const outcome of ['fatal', 'resync_required', 'revoked', 'incompatible']) {
      let connects = 0
      let mode: 'outcome' | 'live' = 'outcome'
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          return 'live'
        },
        loadBootstrap: async () => bootstrap(mode === 'outcome' ? outcome : 'live'),
      })

      await port.connect()
      expect(connects).toBe(1)
      for (let observation = 0; observation < 5; observation += 1) {
        port.observeBootstrap(bootstrap('live'))
        await Promise.resolve()
        await Promise.resolve()
        await Promise.resolve()
      }
      expect(connects).toBe(1)
      expect(port.snapshot().canMutate).toBe(false)

      mode = 'live'
      await port.retry()
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    }

    // Transport-level IPC failures are transient: the closed projection is
    // published for the manual attempt, and automatic recovery self-heals once
    // the transport recovers (no terminal latch, no manual retry required).
    let failing = true
    const port = createRuntimeSessionController({
      connect: async () => {
        if (failing) throw transientReject('ipc unavailable')
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
    failing = false
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  // Regression (live F5 pass): connect_runtime itself rotates the daemon
  // session, so the bootstrap read right after connect can observe
  // Reconciling; the establish must settle through that window instead of
  // failing transient and latching the UI stale.
  it('establishes through the connect-time rotation window', async () => {
    const queue: string[] = ['reconnecting', 'reconnecting', 'live']
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap(queue.shift() ?? 'live'),
    })
    const result = await port.retry()
    expect(result).toMatchObject({ status: 'live', canMutate: true })
    expect(queue).toStrictEqual([])
  })

  // Negative control: a rotation that never settles must keep the session
  // unauthenticated (reconnecting), never clear it to live/stale by fiat.
  it('keeps the session unauthenticated while the rotation never settles', async () => {
    vi.useFakeTimers()
    try {
      const port = createRuntimeSessionController({
        connect: async () => 'live',
        loadBootstrap: async () => bootstrap('reconnecting'),
      })
      const retrying = port.retry()
      const settled = vi.advanceTimersByTimeAsync(10_500)
      const result = await Promise.all([retrying, settled.then(() => undefined)])
      expect(result[0]).toMatchObject({ status: 'reconnecting' })
      expect(port.snapshot()).toMatchObject({ runtime: 'reconnecting', canMutate: false })
    } finally {
      vi.useRealTimers()
    }
  })
})
