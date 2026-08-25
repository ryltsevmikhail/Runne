import { expect, test } from '@playwright/test'

import { installDesktopAdapter, project, workspace } from './replay-resume.support'

test.beforeEach(async ({ page }) => {
  await installDesktopAdapter(page)
})

test('restores the saved workspace through the desktop host boundary', async ({ page }) => {
  await page.goto(`/workspaces/${workspace.workspaceId}`)

  await expect(page.getByRole('heading', { name: workspace.displayName })).toBeVisible()
  await expect(page.getByText(`Version ${workspace.version} · Open`)).toBeVisible()
  await expect(page.locator('.workspace-status')).toHaveText('Runtime live')
  await expect(page.getByText('Runtime session controls this workspace.')).toBeVisible()
  await expect(page.getByText(workspace.workspaceId)).toBeVisible()
  await expect(page.getByText('/workspace/gocode-ui')).toHaveCount(0)
})

test('keeps unknown workspaces closed without leaking saved paths', async ({ page }) => {
  await page.goto('/workspaces/01890e00-0000-7000-8000-000000000099')

  await expect(page.getByRole('alert').filter({ hasText: 'Project unavailable' })).toBeVisible()
  await expect(page.getByText('/workspace/gocode-ui')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Back to projects' })).toBeEnabled()
})

test('creates a workspace through the canonical project mutation flow', async ({ page }) => {
  await page.goto(`/projects/${project.projectId}`)

  await expect(page.getByText('This project has no workspaces yet.')).toBeVisible()
  await page.getByRole('button', { name: 'Create workspace' }).click()
  await expect(page.getByRole('button', { name: 'Open workspace gocode-ui' })).toBeVisible()
})

test('imports a local folder through canonical creation and protected open', async ({ page }) => {
  await page.goto('/projects/open')

  await page.getByRole('button', { name: 'Choose project folder' }).click()

  await expect(page).toHaveURL(new RegExp(`/workspaces/${workspace.workspaceId}$`))
  await expect(page.getByRole('heading', { name: workspace.displayName })).toBeVisible()
})
