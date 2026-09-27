import { TRANSIENT_STATES } from './runtime-session-states'

type ObservedBootstrapClass = 'transient' | 'live' | 'other'

export function createBootstrapRecoveryEdgeTracker() {
  let previous: ObservedBootstrapClass | null = null

  return {
    observe(runtime: string | null): boolean {
      const current: ObservedBootstrapClass = runtime === 'live'
        ? 'live'
        : runtime !== null && TRANSIENT_STATES.has(runtime)
          ? 'transient'
          : 'other'
      const recovered = previous === 'transient' && current === 'live'
      previous = current
      return recovered
    },
    reset(): void {
      previous = null
    },
  }
}
