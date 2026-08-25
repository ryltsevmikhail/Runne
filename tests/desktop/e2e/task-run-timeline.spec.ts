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
        throw new Error('unsupported test command')
      },
    }
  }, { expected: taskRun })
})

test('renders a typed TaskRun timeline without host material', async ({ page }) => {
  await page.goto(`/task-runs/${taskRun.taskRunId}`)

  await expect(page.getByRole('heading', { name: 'succeeded' })).toBeVisible()
  await expect(page.getByLabel('Task run timeline')).toContainText('completed')
  await expect(page.getByText('Terminal result: success')).toBeVisible()
  await expect(page.getByText('private')).toHaveCount(0)
})
