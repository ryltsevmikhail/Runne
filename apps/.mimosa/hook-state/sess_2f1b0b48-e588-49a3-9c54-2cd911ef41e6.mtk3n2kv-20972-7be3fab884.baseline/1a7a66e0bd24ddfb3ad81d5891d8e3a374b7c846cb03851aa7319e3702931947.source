import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import { acquireRendererGeneration, isCanonicalRuntimeId } from './projects'

export type CanonicalProjectDestructiveOperation = 'archive' | 'delete'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
type AcquireGeneration = (invoke: Invoke) => Promise<number>

export async function executeCanonicalProjectDestructiveAction(
  projectId: string,
  expectedVersion: number,
  operation: CanonicalProjectDestructiveOperation,
  acquire: AcquireGeneration = invoke => acquireRendererGeneration(invoke),
  invoke: Invoke = tauriInvoke,
): Promise<void> {
  if (!isCanonicalRuntimeId(projectId) || !Number.isSafeInteger(expectedVersion) || expectedVersion <= 0) {
    throw new Error('Invalid destructive project mutation')
  }
  const rendererGeneration = await acquire(invoke)
  const intent = await invoke('prepare_destructive_project_action', {
    request: { projectId, expectedVersion, operation, rendererGeneration },
  })
  if (!isIntent(intent)) {
    throw new Error('Invalid destructive project intent')
  }
  await invoke('dispatch_destructive_project_action', {
    request: { intent, rendererGeneration },
  })
}

function isIntent(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
}
