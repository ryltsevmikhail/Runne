import { describe, expect, it, vi } from 'vitest'

import { createRuntimeSessionController } from './runtime-session'

const bootstrap = (runtime: string) => ({
  theme: 'dark',
  runtimeMode: 'bundled',
  runtime,
  runtimeLifecycle: 'restarting',
  runtimeFailure: null,
})

function transientError(): Error {
  return Object.assign(new Error('runtime reconnecting'), { disposition: 'transient' })
}

describe('runtime session transient connect settling', () => {
  it('recovers when the protected host becomes ready inside one settle window', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      let rotating = false
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (rotating && connects < 9) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      rotating = true
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(4_000)

      expect(connects).toBe(9)
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('keeps revocation authoritative while a transient connect is waiting', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (connects > 1) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      port.observeBootstrap(bootstrap('reconnecting'))
      await vi.advanceTimersByTimeAsync(0)
      expect(connects).toBe(2)
      port.observeBootstrap(bootstrap('revoked'))
      await vi.advanceTimersByTimeAsync(5_000)

      expect(connects).toBe(2)
      expect(port.snapshot()).toMatchObject({ status: 'revoked', canMutate: false })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('stops the settle window when closed and keeps three windows as a hard bound', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      let closed = false
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (connects > 1 && !closed) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      port.observeBootstrap(bootstrap('reconnecting'))
      await vi.advanceTimersByTimeAsync(0)
      expect(connects).toBe(2)
      await port.close()
      closed = true
      await vi.advanceTimersByTimeAsync(5_000)
      expect(connects).toBe(2)
      expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('bounds persistent transient failures to three settle windows until manual retry', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      let fail = false
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (fail) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      fail = true
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)
      expect(connects).toBe(22)
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)
      expect(connects).toBe(43)
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)
      expect(connects).toBe(64)
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(0)
      expect(connects).toBe(64)

      await port.retry()
      expect(port.snapshot()).toMatchObject({ status: 'unavailable', canMutate: false })
      fail = false
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(0)
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('re-arms one window for a fresh transient-to-live edge after exhaustion', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      let fail = false
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (fail) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      fail = true
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)
      for (let window = 1; window < 3; window += 1) {
        // Repeated live polls consume the remaining bounded windows without
        // manufacturing another transient-to-live edge.
        port.observeBootstrap(bootstrap('live'))
        await vi.advanceTimersByTimeAsync(10_000)
      }
      expect(connects).toBe(64)

      // A repeated live poll alone does not reset the exhausted budget.
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(0)
      expect(connects).toBe(64)

      fail = false
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(0)
      expect(connects).toBe(65)
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('preserves a recovery edge observed while the final window is in flight', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (connects < 65) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)

      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(0)
      expect(connects).toBe(44)
      // This new authoritative edge lands before the third window fails.
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)

      expect(connects).toBe(65)
      expect(port.snapshot()).toMatchObject({ status: 'live', canMutate: true })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('does not re-arm after terminal observation followed by transient and live polls', async () => {
    vi.useFakeTimers()
    try {
      let connects = 0
      const port = createRuntimeSessionController({
        connect: async () => {
          connects += 1
          if (connects > 1) throw transientError()
          return 'live'
        },
        loadBootstrap: async () => bootstrap('live'),
      })

      await port.connect()
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)
      for (let window = 1; window < 3; window += 1) {
        port.observeBootstrap(bootstrap('live'))
        await vi.advanceTimersByTimeAsync(10_000)
      }
      expect(connects).toBe(64)

      port.observeBootstrap(bootstrap('revoked'))
      port.observeBootstrap(bootstrap('reconnecting'))
      port.observeBootstrap(bootstrap('live'))
      await vi.advanceTimersByTimeAsync(10_000)

      expect(connects).toBe(64)
      expect(port.snapshot().canMutate).toBe(false)
    }
    finally {
      vi.useRealTimers()
    }
  })
})
