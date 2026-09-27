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
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('live'),
    })
    const controllerConnect = port.connect.bind(port)
    let releaseResponse: () => void = () => {}
    let signalControllerLive: () => void = () => {}
    const responseHeld = new Promise<void>(resolve => {
      releaseResponse = resolve
    })
    const controllerLive = new Promise<void>(resolve => {
      signalControllerLive = resolve
    })
    port.connect = async () => {
      const result = await controllerConnect()
      signalControllerLive()
      await responseHeld
      return result
    }
    const context = createRuntimeSessionContext(port)

    const pending = context.connect()
    await controllerLive
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    // The controller is live, but its operation response is still held. A
    // revocation must remain authoritative when that stale response is released.
    context.observeBootstrap(bootstrap('revoked'))
    releaseResponse()
    await pending
    expect(context.snapshot.value).toMatchObject({
      status: 'revoked',
      canMutate: false,
    })
  })

  it('never publishes over a close arriving mid-operation', async () => {
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap('live'),
    })
    const controllerConnect = port.connect.bind(port)
    let releaseResponse: () => void = () => {}
    let signalControllerLive: () => void = () => {}
    const responseHeld = new Promise<void>(resolve => {
      releaseResponse = resolve
    })
    const controllerLive = new Promise<void>(resolve => {
      signalControllerLive = resolve
    })
    port.connect = async () => {
      const result = await controllerConnect()
      signalControllerLive()
      await responseHeld
      return result
    }
    const context = createRuntimeSessionContext(port)

    const pending = context.connect()
    await controllerLive
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    await context.close()
    releaseResponse()
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
