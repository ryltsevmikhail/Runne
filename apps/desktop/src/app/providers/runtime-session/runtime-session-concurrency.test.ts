import { describe, expect, it, vi } from 'vitest'

import { createRuntimeSessionController } from './runtime-session'

const bootstrap = (runtime: unknown) => ({
  theme: 'dark',
  runtimeMode: 'external_local',
  runtime,
  runtimeLifecycle: 'external',
  runtimeFailure: null,
})

describe('runtime session concurrency', () => {
  it('keeps the closed snapshot when a pending recovery resolves late', async () => {
    let releaseConnect: ((value: unknown) => void) | undefined
    const port = createRuntimeSessionController({
      connect: () =>
        new Promise(resolve => {
          releaseConnect = resolve
        }),
      loadBootstrap: async () => bootstrap('live'),
    })

    const initial = port.connect()
    releaseConnect?.('live')
    await initial
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await port.close()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })

    releaseConnect?.('live')
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
  })

  it('serializes a manual retry behind a pending recovery and keeps the newer result', async () => {
    let releaseStaleConnect: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (connects === 1) return 'live'
        if (connects === 2) {
          return new Promise(resolve => {
            releaseStaleConnect = resolve
          })
        }
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    // Auto-recovery starts with a deferred connect...
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(2)

    // ...a manual retry waits for the pending recovery instead of racing it...
    const retrying = port.retry()
    releaseStaleConnect?.('reconnecting')
    await retrying
    // ...and then re-authenticates with its own outcome.
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    expect(connects).toBe(3)
  })

  it('keeps a newer revocation read-only when a stale establishment resolves late', async () => {
    let releaseStaleConnect: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (connects === 2) {
          return new Promise(resolve => {
            releaseStaleConnect = resolve
          })
        }
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // A manual re-authentication is in flight when a revocation arrives...
    const retrying = port.retry()
    port.observeBootstrap(bootstrap('revoked'))
    expect(port.snapshot()).toMatchObject({ status: 'revoked', canMutate: false })
    // ...and the stale in-flight result must not restore authentication.
    releaseStaleConnect?.('live')
    await retrying
    await Promise.resolve()
    await Promise.resolve()
    expect(port.snapshot()).toMatchObject({ status: 'revoked', canMutate: false })
  })

  it('does not let a retry awaited before close resurrect the closed session', async () => {
    let releaseRecoveryConnect: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (connects === 1) return 'live'
        if (connects === 2) {
          return new Promise(resolve => {
            releaseRecoveryConnect = resolve
          })
        }
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(2)

    // Manual retry waits for the pending recovery; close happens meanwhile.
    const retrying = port.retry()
    await port.close()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
    releaseRecoveryConnect?.('live')
    await retrying
    await Promise.resolve()
    await Promise.resolve()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
    expect(connects).toBe(3)
    // Late polls after close are ignored until an explicit reopen.
    expect(port.observeBootstrap(bootstrap('live'))).toMatchObject({
      status: 'unavailable',
      canMutate: false,
    })
  })

  it('keeps exactly one automatic recovery in flight under manual retry and repeated live polls', async () => {
    let releaseStaleConnect: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        if (connects === 2) {
          return new Promise(resolve => {
            releaseStaleConnect = resolve
          })
        }
        return 'reconnecting'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(2)

    // Manual retry detaches the pending recovery; repeated live polls must not
    // schedule any automatic recovery while the manual one is pending.
    const retrying = port.retry()
    port.observeBootstrap(bootstrap('live'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(3)
    releaseStaleConnect?.('reconnecting')
    await retrying
    expect(connects).toBe(3)
    expect(port.snapshot()).toMatchObject({ status: 'stale', canMutate: false })
  })

  it('bounds automatic recovery and lets a manual retry reset the budget', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        // The fifth attempt (manual retry) proves live and refreshes the budget.
        if (connects === 1 || connects === 5) return 'live'
        return 'reconnecting'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.observeBootstrap(bootstrap('reconnecting'))).toMatchObject({
      status: 'reconnecting',
      canMutate: false,
    })
    for (let observation = 0; observation < 8; observation += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
    }
    await vi.waitFor(() => {
      expect(connects).toBe(1 + 3)
    })
    expect(port.snapshot().canMutate).toBe(false)

    await port.retry()
    const afterRetry = connects
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(connects).toBe(afterRetry + 1)
    })
  })

  it('never publishes canMutate while a manual establishment awaits its bootstrap', async () => {
    let releaseAutoBootstrap: ((value: unknown) => void) | undefined
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return 'live'
      },
      loadBootstrap: async () => {
        if (connects === 2) {
          return new Promise(resolve => {
            releaseAutoBootstrap = resolve
          })
        }
        return bootstrap('live')
      },
    })

    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await Promise.resolve()
    await Promise.resolve()
    expect(connects).toBe(2)

    // The automatic attempt resolved connect but awaits its bootstrap proof;
    // a manual retry must keep the session read-only until it settles.
    const retrying = port.retry()
    port.observeBootstrap(bootstrap('live'))
    expect(port.snapshot()).toMatchObject({ status: 'stale', canMutate: false })
    releaseAutoBootstrap?.(bootstrap('live'))
    await retrying
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
  })

  it('reopens without waiting for a never-resolving recovery after close', async () => {
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

    await port.close()
    const reopened = port.connect()
    const settled = await Promise.race([
      reopened.then(() => 'settled' as const),
      new Promise<'hung'>(resolve => setTimeout(() => resolve('hung'), 50)),
    ])
    expect(settled).toBe('settled')
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    releaseConnect?.('live')
  })
})
