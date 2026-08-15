import { expect, test } from '@playwright/test'

import { installDesktopAdapter, workspace } from './replay-resume.support'

test.beforeEach(async ({ page }) => {
  await installDesktopAdapter(page)
})

test('restores the saved workspace through the desktop host boundary', async ({ page }) => {
  await page.goto(`/workspaces/${workspace.workspaceId}`)

  await expect(page.getByRole('heading', { name: workspace.displayName })).toBeVisible()
  await expect(page.getByRole('status')).toContainText('Runtime ready')
  await expect(page.getByText('Local workspace')).toBeVisible()
  await expect(page.getByText('Workspace binding is prepared by the desktop host.')).toBeVisible()
  await expect(page.getByText('/workspace/gocode-ui')).toHaveCount(0)
})

test('keeps unknown workspaces closed without leaking saved paths', async ({ page }) => {
  await page.goto('/workspaces/01890e00-0000-7000-8000-000000000099')

  await expect(page.getByRole('alert')).toContainText('Project unavailable')
  await expect(page.getByText('/workspace/gocode-ui')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Back to projects' })).toBeEnabled()
})
