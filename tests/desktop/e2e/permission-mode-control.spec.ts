import { expect, test } from '@playwright/test'

import { installDesktopAdapter, workspace } from './replay-resume.support'

test('mode selector reads in a live read-only session and blocks every change', async ({ page }) => {
  await installDesktopAdapter(page, true)
  await page.addInitScript(() => {
    type Internals = { invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown> }
    type ModeState = { posts: number; reads: number; statusReads: number; commandId: number[] | null }
    type TestWindow = Window & { __TAURI_INTERNALS__: Internals; __permissionModeCalls: ModeState }
    const target = window as TestWindow
    const original = target.__TAURI_INTERNALS__.invoke.bind(target.__TAURI_INTERNALS__)
    const state: ModeState = { posts: 0, reads: 0, statusReads: 0, commandId: null }
    target.__permissionModeCalls = state
    target.__TAURI_INTERNALS__.invoke = async (command, args) => {
      if (command === 'get_permission_mode_status') {
        state.statusReads += 1
        return {
          selectedMode: 'ask_always',
          effective: { state: 'notReady', reason: 'native_containment' },
          authorizationRevision: 4,
          presetVersion: 1,
          managedPolicyVersion: 1,
          pendingApprovalIds: [],
          containment: null,
          networkState: 'unavailable',
          expiresAtUnixMs: null,
        }
      }
      if (command === 'request_permission_mode_change') {
        state.posts += 1
        state.commandId = (args?.request as { commandId: number[] }).commandId
        return { state: 'pending_native_confirmation', commandId: state.commandId, expiresAtUnixMs: 1_800_000_000_000 }
      }
      if (command === 'get_permission_mode_command_status') {
        state.reads += 1
        return { state: 'pending_native_confirmation', commandId: state.commandId, expiresAtUnixMs: 1_800_000_000_000 }
      }
      return original(command, args)
    }
  })
  await page.goto(`/workspaces/${workspace.workspaceId}`)
  await page.getByRole('button', { name: 'Show details', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Permission mode' })).toBeVisible()
  await expect(page.getByText('Native containment is not ready')).toBeVisible()
  const change = page.getByRole('button', { name: 'Confirm for me', exact: true })
  await expect(change).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Ask for permission', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByText('This runtime session is read-only. Mode status is available, but changes are disabled.')).toBeVisible()
  await expect.poll(() => page.evaluate(() => (window as Window & { __permissionModeCalls: { posts: number; reads: number; statusReads: number } }).__permissionModeCalls.statusReads)).toBeGreaterThan(0)
  const calls = await page.evaluate(() => (window as Window & { __permissionModeCalls: { posts: number; reads: number } }).__permissionModeCalls)
  expect(calls).toMatchObject({ posts: 0, reads: 0 })
})
