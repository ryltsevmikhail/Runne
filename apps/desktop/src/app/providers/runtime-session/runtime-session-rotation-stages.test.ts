import { describe, expect, it, vi } from 'vitest'

import { createRuntimeSessionController } from './runtime-session'

const bootstrap = (runtime: string) => ({
  theme: 'dark',
  runtimeMode: 'bundled',
  runtime,
  runtimeLifecycle: 'restarting',
  runtimeFailure: null,
})

const rotationStages = [
  'reconnecting',
  'profile_loaded',
  'peer_verified',
  'bootstrap_proved',
  'authenticated',
  'reconciling',
]

describe('runtime session rotation stages', () => {
  it.each(rotationStages)('recovers after observing %s between live sessions', async stage => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => { connects += 1; return 'live' },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })

    expect(port.observeBootstrap(bootstrap(stage))).toMatchObject({
      runtime: stage,
      canMutate: false,
    })
    expect(port.observeBootstrap(bootstrap('live'))).toMatchObject({
      status: 'stale',
      canMutate: false,
    })

    await vi.waitFor(() => {
      expect(connects).toBe(2)
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('waits through reconciling bootstrap states before proving a fresh session', async () => {
    const states = ['reconciling', 'reconciling', 'live']
    let reads = 0
    const port = createRuntimeSessionController({
      connect: async () => 'live',
      loadBootstrap: async () => bootstrap(states[reads++] ?? 'fatal'),
    })

    expect(await port.connect()).toMatchObject({ status: 'live', canMutate: true })
    expect(reads).toBe(3)
  }, 5_000)

  it('does not prove readiness from an intermediate connect result alone', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => { connects += 1; return connects === 1 ? 'reconciling' : 'live' },
      loadBootstrap: async () => bootstrap('live'),
    })

    expect(await port.connect()).toMatchObject({ status: 'stale', canMutate: false })
    expect(port.observeBootstrap(bootstrap('live')).canMutate).toBe(false)
    await vi.waitFor(() => {
      expect(connects).toBe(2)
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    })
  })

  it('keeps terminal revocation latched across every activation stage', async () => {
    let connects = 0
    const port = createRuntimeSessionController({
      connect: async () => { connects += 1; return 'live' },
      loadBootstrap: async () => bootstrap('live'),
    })

    await port.connect()
    port.observeBootstrap(bootstrap('revoked'))
    for (const stage of rotationStages) {
      port.observeBootstrap(bootstrap(stage))
      port.observeBootstrap(bootstrap('live'))
    }
    await Promise.resolve()
    await Promise.resolve()

    expect(connects).toBe(1)
    expect(port.snapshot()).toMatchObject({ status: 'stale', canMutate: false })
  })
})
