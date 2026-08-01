import { expect, test } from '@playwright/test'

import {
  emitChannel,
  installDesktopAdapter,
  nextUpdate,
  type BrowserReplayAdapter,
} from './replay-resume.support'
test.beforeEach(async ({ page }) => {
  await installDesktopAdapter(page)
  await page.goto('/workspaces/7')
  await expect(page.getByRole('heading', { name: 'gocode-ui' })).toBeVisible()
  await expect(page.getByText('Runtime live', { exact: true }).last()).toBeVisible()
})

test('deduplicates typed channel updates and keeps confirmed history read-only while reconnecting', async ({ page }) => {
  await emitChannel(page, nextUpdate)
  await emitChannel(page, nextUpdate)

  await expect(page.locator('[data-message-id]')).toHaveCount(3)
  await expect(page.locator(`[data-message-id="${nextUpdate.message.messageId}"]`)).toHaveCount(1)
  await expect.poll(async () => page.evaluate(() => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    return replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
      command => command === 'ack_conversation_update',
    ).length
  })).toBe(2)

  await emitChannel(page, {
    kind: 'error',
    code: 'conversation_subscription_unavailable',
  })

  await expect(page.getByText('Reconnecting — confirmed messages remain read-only.')).toBeVisible()
  await expect(page.locator('[data-message-id]')).toHaveCount(3)
  await expect(page.getByRole('textbox', { name: 'Message' })).toBeDisabled()
})

test('runs explicit resync through the native command and restores the live composer', async ({ page }) => {
  await emitChannel(page, {
    kind: 'error',
    code: 'replay_resync_required',
  })

  await expect(page.getByText('Conversation resync is required.')).toBeVisible()
  await expect(page.locator('[data-message-id]')).toHaveCount(2)
  await expect(page.getByRole('textbox', { name: 'Message' })).toBeDisabled()
  await page.getByRole('button', { name: 'Resync' }).click()
  await expect(page.getByText('Reconnecting — confirmed messages remain read-only.')).toBeVisible()
  await expect(page.getByText('Runtime live', { exact: true }).last()).toBeVisible()
  await expect(page.getByRole('textbox', { name: 'Message' })).toBeEnabled()
  await expect.poll(async () => page.evaluate(() => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    return {
      opens: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'open_project_conversation',
      ).length,
      resyncs: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'resync_project_conversation',
      ).length,
      subscribes: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'subscribe_project_conversation',
      ).length,
    }
  })).toEqual({ opens: 1, resyncs: 1, subscribes: 2 })
})

test('keeps explicit resync actionable when the native command fails', async ({ page }) => {
  await page.evaluate(() => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    replayWindow.__GOCODE_REPLAY_TEST__.resyncShouldFail = true
  })
  await emitChannel(page, {
    kind: 'error',
    code: 'replay_resync_required',
  })

  await page.getByRole('button', { name: 'Resync' }).click()
  await expect(page.getByText('Reconnecting — confirmed messages remain read-only.')).toBeVisible()
  await expect(page.getByText('Conversation resync is required.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Resync' })).toBeEnabled()
  await expect(page.getByRole('textbox', { name: 'Message' })).toBeDisabled()
  await expect.poll(async () => page.evaluate(() => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    return {
      opens: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'open_project_conversation',
      ).length,
      resyncs: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'resync_project_conversation',
      ).length,
      subscribes: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'subscribe_project_conversation',
      ).length,
    }
  })).toEqual({ opens: 1, resyncs: 1, subscribes: 1 })
})

test('keeps explicit resync actionable when replacement subscription fails after open', async ({ page }) => {
  await page.evaluate(() => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    replayWindow.__GOCODE_REPLAY_TEST__.resyncSubscriptionShouldFail = true
  })
  await emitChannel(page, {
    kind: 'error',
    code: 'replay_resync_required',
  })

  await page.getByRole('button', { name: 'Resync' }).click()
  await expect(page.getByText('Reconnecting — confirmed messages remain read-only.')).toBeVisible()
  await expect(page.getByText('Conversation resync is required.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Resync' })).toBeEnabled()
  await expect(page.getByRole('textbox', { name: 'Message' })).toBeDisabled()
  await expect.poll(async () => page.evaluate(() => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    return {
      opens: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'open_project_conversation',
      ).length,
      resyncs: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'resync_project_conversation',
      ).length,
      subscribes: replayWindow.__GOCODE_REPLAY_TEST__.calls.filter(
        command => command === 'subscribe_project_conversation',
      ).length,
    }
  })).toEqual({ opens: 1, resyncs: 1, subscribes: 2 })
})

test('maps authorization epoch revocation to the closed revoked UI state', async ({ page }) => {
  await emitChannel(page, {
    kind: 'error',
    code: 'runtime_revoked',
  })

  await expect(page.getByText('Runtime access was revoked.')).toBeVisible()
  await expect(page.locator('[data-message-id]')).toHaveCount(2)
  await expect(page.getByRole('textbox', { name: 'Message' })).toBeDisabled()
})
