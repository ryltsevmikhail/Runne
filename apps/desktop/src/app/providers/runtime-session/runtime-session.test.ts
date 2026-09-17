import { describe, expect, it, vi } from 'vitest'

import { createRuntimeSessionController, createRuntimeSessionPort } from './runtime-session'

const bootstrap = (runtime: unknown) => ({
  theme: 'dark',
  runtimeMode: 'external_local',
  runtime,
  runtimeLifecycle: 'external',
  runtimeFailure: null,
})

describe('runtime session port', () => {
  it('does not expose live state before the authenticated connection completes', async () => {
    let completeHandshake: (() => void) | undefined
    const port = createRuntimeSessionPort({
      connect: async () => new Promise(resolve => {
        completeHandshake = () => resolve('live')
      }),
      loadBootstrap: async () => bootstrap('live'),
    })

    const connecting = port.connect()

    expect(port.snapshot().status).toBe('loading')
    expect(port.snapshot().canMutate).toBe(false)

    completeHandshake?.()
    await connecting

    expect(port.snapshot().status).toBe('live')
    expect(port.snapshot().canMutate).toBe(true)
  })

  it('keeps stale projections read-only and fails closed for unknown runtime states', async () => {
    const stale = createRuntimeSessionPort({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('resync_required'),
    })
    const unknown = createRuntimeSessionPort({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('not-a-runtime-state'),
    })

    await stale.connect()
    await unknown.connect()

    expect(stale.snapshot()).toMatchObject({ status: 'stale', canMutate: false })
    expect(unknown.snapshot()).toMatchObject({ status: 'fatal', canMutate: false })
  })

  it('revokes mutation permission when a later runtime observation leaves live', async () => {
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    for (const [runtime, status] of [
      ['reconnecting', 'reconnecting'],
      ['revoked', 'revoked'],
      ['resync_required', 'stale'],
      ['fatal', 'fatal'],
    ] as const) {
      expect(port.observeBootstrap(bootstrap(runtime))).toMatchObject({
        runtime,
        status,
        canMutate: false,
      })
    }

    expect(port.snapshot()).toMatchObject({ status: 'fatal', canMutate: false })
  })

  // The establish now spends up to ~10 s settling through the connect-time
  // rotation window before reporting; the poll invariant (live without a
  // fresh authenticated connect stays stale/read-only) is unchanged.
  it('requires a fresh authenticated connect after bootstrap reports reconnecting', { timeout: 12_000 }, async () => {
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('reconnecting'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'reconnecting', canMutate: false })

    expect(port.observeBootstrap(bootstrap('live'))).toMatchObject({
      status: 'stale',
      canMutate: false,
    })
  })

  it('requires a fresh authenticated connect after initial bootstrap fails', async () => {
    let bootstrapFails = true
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => {
        if (bootstrapFails) {
          bootstrapFails = false
          throw new Error('bootstrap unavailable')
        }
        return bootstrap('live')
      },
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })

    expect(port.observeBootstrap(bootstrap('live'))).toMatchObject({
      status: 'stale',
      canMutate: false,
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
  })

  it('re-authenticates automatically after a transient reconnect window resolves', async () => {
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    expect(port.observeBootstrap(bootstrap('reconnecting'))).toMatchObject({
      status: 'reconnecting',
      canMutate: false,
    })
    // Synchronous contract: an observed live bootstrap alone is still stale...
    expect(port.observeBootstrap(bootstrap('live'))).toMatchObject({
      status: 'stale',
      canMutate: false,
    })
    // ...but the controller schedules one authenticated reconnect by itself,
    // so a renewed or reconnected runtime stops being read-only without a
    // manual retry.
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('keeps a terminal latch across later transient observations', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(connects).toBe(1)

    // A revocation latches; a transient observation must not clear it.
    port.observeBootstrap(bootstrap('revoked'))
    port.observeBootstrap(bootstrap('reconnecting'))
    for (let observation = 0; observation < 5; observation += 1) {
      port.observeBootstrap(bootstrap('live'))
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    }
    expect(connects).toBe(1)
    expect(port.snapshot().canMutate).toBe(false)

    // A manual retry re-arms recovery; a later transient cycle auto-heals.
    await port.retry()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('latches terminal connect outcomes against automatic recovery', async () => {
    for (const connected of ['revoked', 'incompatible', 'fatal', 'resync_required', 'garbage']) {
      let connects = 0
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          return connected
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
      expect(port.snapshot().canMutate).toBe(false)
      await port.retry()
      expect(connects).toBe(2)
    }

    // A reconnecting handshake outcome stays recoverable.
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => {
        connects += 1
        return connects === 1 ? 'reconnecting' : 'live'
      },
      loadBootstrap: async () => bootstrap('live'),
    })
    await port.connect()
    port.observeBootstrap(bootstrap('reconnecting'))
    port.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => {
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('drops pre-close bootstrap reads delivered after a reopen', async () => {
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    const staleTicket = port.sessionTicket()
    await port.close()
    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // A read captured before the close must not fence the new session...
    expect(port.observeBootstrap(bootstrap('revoked'), staleTicket)).toMatchObject({
      status: 'live',
      canMutate: true,
    })
    // ...a read captured before a new establishment is fenced the same way...
    const preRetryTicket = port.sessionTicket()
    await port.retry()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    expect(port.observeBootstrap(bootstrap('revoked'), preRetryTicket)).toMatchObject({
      status: 'live',
      canMutate: true,
    })
    // ...while the current generation still applies.
    expect(port.observeBootstrap(bootstrap('revoked'), port.sessionTicket())).toMatchObject({
      status: 'revoked',
      canMutate: false,
    })
  })

  it('fences reads captured before an establishment still in flight', async () => {
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
    const staleTicket = port.sessionTicket()
    const retrying = port.retry()
    // The transition fences older reads immediately, not on completion.
    expect(port.observeBootstrap(bootstrap('revoked'), staleTicket)).toMatchObject({
      status: 'loading',
      canMutate: false,
    })
    releaseConnect?.('live')
    await retrying
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
  })
})
