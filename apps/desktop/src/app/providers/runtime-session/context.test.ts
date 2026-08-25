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
})
