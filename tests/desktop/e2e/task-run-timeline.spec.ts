import { expect, test } from '@playwright/test'

const taskRun = {
  taskRunId: '018f2e3a-7000-7000-8000-000000000210',
  projectionRevision: 1,
  streamVersion: 1,
  state: 'succeeded',
  activeAttemptId: null,
  terminal: 'success',
  entries: [{
    eventId: '018f2e3a-7000-7000-8000-000000000212',
    sequence: 1,
    committedAt: 1,
    kind: 'completed',
    attemptId: null,
  }],
  recovery: 'live',
} as const

test.beforeEach(async ({ page }) => {
  await page.addInitScript(({ expected }) => {
    type TauriInternals = { invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown>, transformCallback: () => number, unregisterCallback: () => void, convertFileSrc: (path: string) => string }
    ;(globalThis as typeof globalThis & { isTauri: boolean }).isTauri = true
    ;(window as Window & { __TAURI_INTERNALS__: TauriInternals }).__TAURI_INTERNALS__ = {
      transformCallback: () => 1,
      unregisterCallback: () => {},
      convertFileSrc: path => path,
      async invoke(command, args) {
        if (command === 'get_bootstrap') return { theme: 'dark', runtimeMode: 'bundled', runtime: 'live', runtimeLifecycle: 'ready', runtimeFailure: null }
        if (command === 'connect_runtime') return 'live'
        if (command === 'get_task_run_timeline' && args?.taskRunId === expected.taskRunId) return expected
        if (command === 'subscribe_task_run_timeline' && args?.taskRunId === expected.taskRunId) return '018f2e3a-7000-7000-8000-000000000220'
        if (command === 'cancel_task_run_subscription' && args?.subscriptionId === '018f2e3a-7000-7000-8000-000000000220') return null
        if (command === 'get_task_run_effects' && args?.taskRunId === expected.taskRunId) return {
          taskRunId: expected.taskRunId,
          streamVersion: expected.streamVersion,
          attemptId: null,
          cancellationRequested: false,
          localCommand: null,
          remote: {
            outcome: 'unknown',
            publication: 'unknown',
            accounting: 'unknown',
            cancellation: 'unknown',
            availability: 'unknown',
            capabilities: { statusCheck: false, streamResume: false, remoteCancel: false },
            usageKnown: null,
          },
          successor: 'blocked',
        }
        throw new Error('unsupported test command')
      },
    }
  }, { expected: taskRun })
})

test('renders a typed TaskRun timeline without host material', async ({ page }) => {
  await page.goto(`/task-runs/${taskRun.taskRunId}`)

  await expect(page.getByRole('heading', { name: 'completed' })).toBeVisible()
  await expect(page.getByLabel('Task run timeline')).toContainText('completed')
  await expect(page.getByText('Terminal result: success')).toBeVisible()
  await expect(page.getByText('Remote outcome: unknown')).toBeVisible()
  await expect(page.getByText('Execution effects are unavailable')).toHaveCount(0)
  await expect(page.getByText('Connection to the task stream was lost.')).toHaveCount(0)
  await expect(page.getByText('private')).toHaveCount(0)
})
