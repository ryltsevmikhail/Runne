import { expect, test } from '@playwright/test'
import type { ActivationTarget } from '../../../apps/desktop/src/shared/api/platform/external-activation'
import { managedWorkspace as workspace, taskRunId } from './managed-task-composer.support'
import { hostObservations, installHostControl, releaseWorkspace, secondWorkspace, setRuntime } from './router-host.support'
import { attachRoutingEvidence, installRouterPort, navigate, snapshot } from './router-navigation.support'

test.afterEach(async ({ page }, info) => { await attachRoutingEvidence(page, info) })

const empty: ActivationTarget = { runtime: null, projectId: null, workspaceId: null, taskRunId: null, approvalId: null, event: null }
const activationRows: { label: string; target: ActivationTarget; destination: string }[] = [
  { label: 'TaskRun over approval/workspace/project', target: { ...empty, taskRunId, approvalId: taskRunId, workspaceId: workspace.workspaceId, projectId: workspace.projectId, event: 'approval' }, destination: `/task-runs/${taskRunId}` },
  { label: 'approval over workspace/project', target: { ...empty, approvalId: taskRunId, workspaceId: workspace.workspaceId, projectId: workspace.projectId }, destination: '/approvals' },
  { label: 'approval event over workspace', target: { ...empty, workspaceId: workspace.workspaceId, event: 'approval' }, destination: '/approvals' },
  { label: 'workspace over project', target: { ...empty, workspaceId: workspace.workspaceId, projectId: workspace.projectId }, destination: `/workspaces/${workspace.workspaceId}` },
  { label: 'project redirect', target: { ...empty, projectId: workspace.projectId }, destination: `/?project=${workspace.projectId}` },
]
for (const row of activationRows) {
  test(`pending typed activation selects ${row.label} only after live`, async ({ page }) => {
    await page.clock.install()
    await installHostControl(page, { pending: row.target, holdConnect: true })
    await page.goto('/recovery')
    await expect.poll(async () => (await hostObservations(page)).held).toBe(1)
    const beforeLive = await hostObservations(page)
    expect(beforeLive.unresolved).toBe(1)
    expect(beforeLive.settled).toBe(0)
    expect(beforeLive.barriers).toEqual([{ command: 'connect_runtime', workspaceId: null, phase: 'held' }])
    await expect(page).toHaveURL('http://127.0.0.1:1420/recovery')
    await expect(page.getByRole('heading', { name: 'Project recovery', exact: true })).toBeVisible()
    await expect(page.locator('.runtime-status')).toHaveAttribute('data-session-proven', 'false')
    expect(beforeLive.calls.some(call => /^(start_|send_|save_|clear_|set_permission|approve_|cancel_process)/.test(call.command))).toBe(false)
    const beforeLength = await page.evaluate(() => history.length)
    await releaseWorkspace(page)
    await expect.poll(async () => (await hostObservations(page)).settled).toBe(1)
    expect((await hostObservations(page)).unresolved).toBe(0)
    await expect(page.locator('.runtime-status')).toHaveAttribute('data-session-proven', 'true')
    await expect(page).toHaveURL(`http://127.0.0.1:1420${row.destination}`)
    expect(await page.evaluate(() => history.length)).toBe(beforeLength + 1)
    const calls = (await hostObservations(page)).calls.map(call => call.command)
    expect(calls.indexOf('get_pending_external_activation')).toBeLessThan(calls.indexOf('connect_runtime'))
    expect(calls.filter(command => command === 'get_pending_external_activation')).toHaveLength(1)
    const historyLength = await page.evaluate(() => history.length)
    await page.clock.runFor(2_000)
    await expect(page).toHaveURL(`http://127.0.0.1:1420${row.destination}`)
    expect(await page.evaluate(() => history.length)).toBe(historyLength)
    expect((await hostObservations(page)).failures).toEqual([])
    await test.info().attach('activation-held-before-live', { body: JSON.stringify({ beforeLive, afterLive: await hostObservations(page), beforeLength, historyLength }), contentType: 'application/json' })
  })
}

test('foreign runtime activation renders reconciliation notice without switching context', async ({ page }) => {
  await installHostControl(page, { pending: { ...empty, runtime: 'foreign-runtime', workspaceId: workspace.workspaceId } })
  await page.goto('/recovery')
  await expect(page.locator('.app-shell__activation-notice')).toBeVisible()
  await expect(page).toHaveURL('http://127.0.0.1:1420/recovery')
  expect((await hostObservations(page)).calls.filter(call => call.command === 'connect_runtime')).toHaveLength(1)
  expect((await hostObservations(page)).calls.some(call => (JSON.stringify(call.args) ?? '').includes('foreign-runtime'))).toBe(false)
})

for (const pending of [
  { ...empty, workspaceId: 'not-canonical' },
  { ...empty, workspaceId: workspace.workspaceId, extra: true },
  { ...empty, runtime: '../foreign', projectId: workspace.projectId },
]) {
  test(`malformed typed activation is ignored: ${JSON.stringify(pending)}`, async ({ page }) => {
    await page.clock.install()
    await installHostControl(page, { pending })
    await page.goto('/recovery')
    await expect(page.locator('.runtime-status')).toHaveAttribute('data-session-proven', 'true')
    await page.clock.runFor(1_000)
    await expect(page).toHaveURL('http://127.0.0.1:1420/recovery')
    await expect(page.locator('.app-shell__activation-notice')).toHaveCount(0)
    expect((await hostObservations(page)).failures).toEqual([])
  })
}

for (const state of ['revoked', 'fatal', 'resync_required'] as const) {
  test(`deep workspace stays read-only after ${state} then live until explicit retry`, async ({ page }) => {
    await page.clock.install()
    await installHostControl(page)
    const path = `/workspaces/${workspace.workspaceId}`
    await page.goto(path)
    const message = page.getByRole('textbox', { name: 'Message', exact: true })
    await expect(message).toBeEnabled()
    await message.fill('retain local workspace draft')
    await setRuntime(page, state)
    await page.clock.runFor(1_000)
    await expect(message).toBeDisabled()
    await setRuntime(page, 'live')
    await page.clock.runFor(2_000)
    await expect(message).toBeDisabled()
    await expect(page.locator('.runtime-status')).toHaveAttribute('data-session-proven', 'false')
    expect((await hostObservations(page)).calls.filter(call => call.command === 'connect_runtime')).toHaveLength(1)
    await page.locator('.sidebar-projects__retry').click()
    await expect(message).toBeEnabled()
    await expect(message).toHaveValue('retain local workspace draft')
    await expect(page).toHaveURL(`http://127.0.0.1:1420${path}`)
    const calls = (await hostObservations(page)).calls
    expect(calls.filter(call => call.command === 'connect_runtime')).toHaveLength(2)
    expect(calls.filter(call => call.command === 'start_managed_task_run' || call.command === 'send_workspace_message')).toHaveLength(0)
  })
}

test('transient reconnect preserves the same workspace draft and does not submit it', async ({ page }) => {
  await page.clock.install()
  await installHostControl(page)
  await page.goto(`/workspaces/${workspace.workspaceId}`)
  const message = page.getByRole('textbox', { name: 'Message', exact: true })
  await expect(message).toBeEnabled()
  await message.fill('transient draft')
  await setRuntime(page, 'reconnecting')
  await page.clock.runFor(1_000)
  await expect(message).toBeDisabled()
  await setRuntime(page, 'live')
  await page.clock.runFor(2_000)
  await expect(message).toBeEnabled()
  await expect(message).toHaveValue('transient draft')
  await expect(page).toHaveURL(`http://127.0.0.1:1420/workspaces/${workspace.workspaceId}`)
  expect((await hostObservations(page)).calls.filter(call => call.command === 'start_managed_task_run' || call.command === 'send_workspace_message')).toHaveLength(0)
})

test('late workspace A lookup cannot overwrite B or populate its draft', async ({ page }) => {
  await installHostControl(page, { holdWorkspace: true })
  await installRouterPort(page)
  await page.goto(`/workspaces/${workspace.workspaceId}`)
  await expect.poll(async () => (await hostObservations(page)).held).toBeGreaterThan(0)
  await navigate(page, `/workspaces/${secondWorkspace.workspaceId}`)
  await expect(page.getByRole('heading', { name: secondWorkspace.displayName })).toBeVisible()
  const message = page.getByRole('textbox', { name: 'Message', exact: true })
  await expect(message).toHaveValue('')
  await message.fill('only B draft')
  const held = await hostObservations(page)
  expect(held.unresolved).toBe(held.held)
  expect(held.settled).toBe(0)
  await releaseWorkspace(page)
  await expect.poll(async () => (await hostObservations(page)).unresolved).toBe(0)
  expect((await hostObservations(page)).settled).toBe(held.held)
  await expect(page.getByRole('heading', { name: secondWorkspace.displayName })).toBeVisible()
  await expect(message).toHaveValue('only B draft')
  expect((await snapshot(page)).params.workspaceId).toBe(secondWorkspace.workspaceId)
})

for (const module of ['app/startup.ts', 'main.ts']) {
  test(`deep startup ${module} failure is sanitized and recovers through offered root link`, async ({ page }) => {
    await installHostControl(page)
    const pattern = `**/src/${module}`
    await page.route(pattern, route => module === 'main.ts'
      ? route.fulfill({ contentType: 'text/javascript', body: 'throw new Error("PRIVATE_HOST_PATH=/private/fixture-secret")' })
      : route.abort())
    await page.goto(`/workspaces/${workspace.workspaceId}`)
    const status = page.locator('#startup-status')
    await expect(status).toBeVisible()
    await expect(status).toContainText('Runne couldn’t start')
    await expect(status).toContainText(module === 'main.ts'
      ? 'Part of the app failed to load. Refresh the page to try again.'
      : 'The app has not loaded yet. Refresh the page to try again.')
    await expect(page.locator('body')).not.toContainText('PRIVATE_HOST_PATH')
    await page.unroute(pattern)
    await status.getByRole('link').click()
    await expect(page).toHaveURL('http://127.0.0.1:1420/')
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible()
    await expect(status).toHaveCount(0)
  })
}
