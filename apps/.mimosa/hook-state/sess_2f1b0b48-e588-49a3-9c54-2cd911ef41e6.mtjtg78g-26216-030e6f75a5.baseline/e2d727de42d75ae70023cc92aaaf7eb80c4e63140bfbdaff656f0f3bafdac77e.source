import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import type { OperationalTelemetrySnapshot } from './operational-telemetry.types'
import { parseOperationalTelemetry } from './operational-telemetry.validation'

export type { OperationalTelemetrySnapshot } from './operational-telemetry.types'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function getOperationalTelemetry(
  invoke: Invoke = tauriInvoke,
): Promise<OperationalTelemetrySnapshot> {
  const snapshot = parseOperationalTelemetry(await invoke('get_operational_telemetry'))
  if (snapshot === null) throw new Error('Invalid operational telemetry response')
  return snapshot
}
