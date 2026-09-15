import { describe, expect, it, vi } from 'vitest'

import { createRuntimeSessionController } from './runtime-session'

const bootstrap = (runtime: unknown) => ({
  theme: 'dark',
  runtimeMode: 'external_local',
  runtime,
  runtimeLifecycle: 'external',
  runtimeFailure: null,
})

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

    // An IPC failure outcome denies automatic recovery the same way.
    let connects = 0
    let failing = true
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (failing) throw new Error('ipc unavailable')
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
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
    failing = false
    await port.retry()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
  })
})
