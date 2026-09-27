import { createBootstrapRecoveryEdgeTracker } from './bootstrap-recovery-edge'

const MAX_AUTOMATIC_RECOVERIES = 3

export function createAutomaticRecoveryBudget() {
  let failures = 0
  let rearmAfterWindow = false
  const bootstrapEdge = createBootstrapRecoveryEdgeTracker()

  return {
    canRecover(): boolean {
      return failures < MAX_AUTOMATIC_RECOVERIES
    },
    resetForManual(): void {
      failures = 0
      rearmAfterWindow = false
      bootstrapEdge.reset()
    },
    resetAfterProof(): void {
      failures = 0
    },
    observeBootstrap(
      runtime: string | null,
      canRearm: boolean,
      recoveryInFlight: boolean,
    ): boolean {
      const recovered = bootstrapEdge.observe(runtime)
      if (!recovered || !canRearm || failures < MAX_AUTOMATIC_RECOVERIES - 1) {
        return false
      }
      if (recoveryInFlight) {
        rearmAfterWindow = true
        return false
      }
      if (failures >= MAX_AUTOMATIC_RECOVERIES) {
        failures = MAX_AUTOMATIC_RECOVERIES - 1
        return true
      }
      return false
    },
    finishWindow(live: boolean, canRearm: boolean): boolean {
      if (live) {
        failures = 0
        rearmAfterWindow = false
        return false
      }
      failures += 1
      const shouldRearm = rearmAfterWindow && canRearm
      rearmAfterWindow = false
      if (!shouldRearm) return false
      failures = MAX_AUTOMATIC_RECOVERIES - 1
      return true
    },
    cancelPending(): void {
      rearmAfterWindow = false
      bootstrapEdge.reset()
    },
  }
}
