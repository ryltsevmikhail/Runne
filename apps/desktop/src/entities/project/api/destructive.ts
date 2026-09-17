import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import { projectsRevision } from './canonical-projects'
import { acquireRendererGeneration, isCanonicalRuntimeId } from './projects'
import { currentLocale } from '@/shared/i18n'

export type CanonicalProjectDestructiveOperation = 'archive' | 'delete'
export type CanonicalProjectDestructiveOutcome = 'completed' | 'cancelled'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
type AcquireGeneration = (invoke: Invoke) => Promise<number>

export async function executeCanonicalProjectDestructiveAction(
  projectId: string,
  expectedVersion: number,
  operation: CanonicalProjectDestructiveOperation,
  acquire: AcquireGeneration = invoke => acquireRendererGeneration(invoke),
  invoke: Invoke = tauriInvoke,
): Promise<CanonicalProjectDestructiveOutcome> {
  if (!isCanonicalRuntimeId(projectId) || !Number.isSafeInteger(expectedVersion) || expectedVersion <= 0) {
    throw new Error('Invalid destructive project mutation')
  }
  const rendererGeneration = await acquire(invoke)
  let intent: unknown
  try {
    intent = await invoke('prepare_destructive_project_action', {
      request: { projectId, expectedVersion, operation, rendererGeneration, locale: currentLocale.value },
    })
  }
  catch (error) {
    if (isDestructiveActionCancelled(error)) return 'cancelled'
    throw error
  }
  if (!isIntent(intent)) {
    throw new Error('Invalid destructive project intent')
  }
  await invoke('dispatch_destructive_project_action', {
    request: { intent, rendererGeneration },
  })
  projectsRevision.value += 1
  return 'completed'
}

function isDestructiveActionCancelled(error: unknown): boolean {
  if (error === 'destructive_action_cancelled') return true
  if (typeof error !== 'object' || error === null) return false
  return (error as { code?: unknown }).code === 'destructive_action_cancelled'
}

function isIntent(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
}
