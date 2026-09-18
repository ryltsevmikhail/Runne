import { describe, expect, it } from 'vitest'

import { createRuntimeSessionContext } from './context'
import { createRuntimeSessionController } from './runtime-session'

const bootstrap = (runtime: unknown) => ({ runtime })

describe('runtime session context', () => {
  it('publishes runtime observations after the initial connection', async () => {
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('live'),
    })
    const context = createRuntimeSessionContext(port)

    await context.connect()
    context.observeBootstrap(bootstrap('reconnecting'))

    expect(context.snapshot.value).toMatchObject({
      status: 'reconnecting',
      canMutate: false,
    })
  })

  it('never publishes a stale live over a revocation arriving mid-operation', async () => {
    let releaseBootstrap: (value: unknown) => void = () => {}
    const deferredBootstrap = new Promise(resolve => {
      releaseBootstrap = resolve
    })
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: () => deferredBootstrap,
    })
    const context = createRuntimeSessionContext(port)

    const pending = context.connect()
    await Promise.resolve() // reach the deferred loadBootstrap
    releaseBootstrap(bootstrap('live'))
    await Promise.resolve() // establish resumes and publishes live
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // A revocation arrives before the operation settles externally: the context
    // must publish the controller's current (read-only) state, not the stale
    // live return value.
    context.observeBootstrap(bootstrap('revoked'))
    await pending
    expect(context.snapshot.value).toMatchObject({
      status: 'revoked',
      canMutate: false,
    })
  })

  it('never publishes over a close arriving mid-operation', async () => {
    let releaseBootstrap: (value: unknown) => void = () => {}
    const deferredBootstrap = new Promise(resolve => {
      releaseBootstrap = resolve
    })
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: () => deferredBootstrap,
    })
    const context = createRuntimeSessionContext(port)

    const pending = context.connect()
    await Promise.resolve() // reach the deferred loadBootstrap
    releaseBootstrap(bootstrap('live'))
    await Promise.resolve() // establish resumes and publishes live
    await context.close()
    await pending
    expect(context.snapshot.value).toMatchObject({
      status: 'unavailable',
      canMutate: false,
    })
  })

  it('drops canMutate synchronously when a manual retry starts from live', async () => {
    let releaseConnect: (value: unknown) => void = () => {}
    const port = createRuntimeSessionController({
      connect: () => new Promise(resolve => {
        releaseConnect = resolve
      }),
      loadBootstrap: async () => bootstrap('live'),
    })

    const context = createRuntimeSessionContext(port)
    await (async () => {
      const initial = context.connect()
      releaseConnect('live')
      await initial
    })()
    expect(context.snapshot.value.canMutate).toBe(true)

    // Starting the retry must synchronously project the controller's loading
    // state: consumers cannot keep sending on the previous proof.
    const retrying = context.retry()
    expect(context.snapshot.value).toMatchObject({ status: 'loading', canMutate: false })

    releaseConnect('live')
    await retrying
    expect(context.snapshot.value).toMatchObject({ status: 'live', canMutate: true })
  })
})
