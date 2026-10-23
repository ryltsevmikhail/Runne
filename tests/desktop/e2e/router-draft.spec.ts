import { expect, test } from '@playwright/test'
import { managedWorkspace as workspace } from './managed-task-composer.support'
import { hostObservations, installHostControl, releaseWorkspace, secondWorkspace } from './router-host.support'
import { attachRoutingEvidence, installRouterPort, navigate, snapshot } from './router-navigation.support'

test.afterEach(async ({ page }, info) => { await attachRoutingEvidence(page, info) })

// Removing the real DraftSession operation/scope fence must expose A's late plaintext in B.
test('late durable A draft load cannot overwrite B, persist A under B, or seize its route', async ({ page }) => {
  await page.clock.install()
  await installHostControl(page, { durable: true, holdDraft: 'load' })
  await installRouterPort(page)
  await page.goto(`/workspaces/${workspace.workspaceId}`)
  await expect.poll(async () => (await hostObservations(page)).held).toBe(1)
  const held = await hostObservations(page)
  expect(held.unresolved).toBe(1)
  expect(held.settled).toBe(0)
  expect(held.barriers).toEqual([{ command: 'load_managed_task_draft', workspaceId: workspace.workspaceId, phase: 'held' }])
  expect(held.calls.filter(call => call.command === 'load_managed_task_draft')).toEqual([
    { command: 'load_managed_task_draft', args: { projectId: workspace.projectId, workspaceId: workspace.workspaceId } },
  ])
  await navigate(page, `/workspaces/${secondWorkspace.workspaceId}`)
  await expect(page.getByRole('heading', { name: secondWorkspace.displayName })).toBeVisible()
  const message = page.getByRole('textbox', { name: 'Task', exact: true })
  await expect(message).toBeEnabled()
  await expect(message).toHaveValue('saved B private draft')
  await message.fill('only B edited durable draft')
  await page.clock.runFor(1_000)
  await expect.poll(async () => (await hostObservations(page)).drafts[secondWorkspace.workspaceId]?.prompt).toBe('only B edited durable draft')
  const beforeRelease = await hostObservations(page)
  expect(beforeRelease.unresolved).toBe(1)
  expect(beforeRelease.settled).toBe(0)
  const historyLength = await page.evaluate(() => history.length)
  await releaseWorkspace(page)
  await expect.poll(async () => (await hostObservations(page)).settled).toBe(1)
  expect((await hostObservations(page)).unresolved).toBe(0)
  await expect(message).toHaveValue('only B edited durable draft')
  await message.fill('B after late A completion')
  await page.clock.runFor(1_000)
  await expect.poll(async () => (await hostObservations(page)).drafts[secondWorkspace.workspaceId]?.prompt).toBe('B after late A completion')
  await expect(page).toHaveURL(`http://127.0.0.1:1420/workspaces/${secondWorkspace.workspaceId}`)
  expect((await snapshot(page)).params.workspaceId).toBe(secondWorkspace.workspaceId)
  expect(await page.evaluate(() => history.length)).toBe(historyLength)
  const final = await hostObservations(page)
  expect(final.drafts[workspace.workspaceId]).toEqual({ revision: 3, prompt: 'saved A private draft', scopeToken: 'a'.repeat(64) })
  expect(final.drafts[secondWorkspace.workspaceId]).toEqual({ revision: 9, prompt: 'B after late A completion', scopeToken: 'b'.repeat(64) })
  const writes = final.calls.filter(call => call.command === 'save_managed_task_draft')
  expect(writes.map(call => call.args)).toEqual([
    { projectId: workspace.projectId, workspaceId: secondWorkspace.workspaceId, scopeToken: 'b'.repeat(64), expectedRevision: 7, prompt: 'only B edited durable draft' },
    { projectId: workspace.projectId, workspaceId: secondWorkspace.workspaceId, scopeToken: 'b'.repeat(64), expectedRevision: 8, prompt: 'B after late A completion' },
  ])
  expect(final.calls.some(call => /^(start_|send_|clear_|set_permission|approve_|cancel_process)/.test(call.command))).toBe(false)
  expect(final.failures).toEqual([])
  await test.info().attach('durable-barriers-and-writes', { body: JSON.stringify({ held, beforeRelease, final }), contentType: 'application/json' })
})
