import { describe, expect, it } from 'vitest'

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

  it('requires a fresh authenticated connect after bootstrap reports reconnecting', async () => {
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
})
