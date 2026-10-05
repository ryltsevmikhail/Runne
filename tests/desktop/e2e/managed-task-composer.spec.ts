import { expect, test } from '@playwright/test'
import { installManagedComposerAdapter, managedWorkspace, recoveryToken, taskRunId } from './managed-task-composer.support'

test('starts from the real workspace composer and opens its canonical TaskRun', async ({ page }) => {
  await installManagedComposerAdapter(page)
  await page.goto(`/workspaces/${managedWorkspace.workspaceId}`)

  const prompt = page.getByRole('textbox', { name: 'Task' })
  await expect(page.getByText('Effective provider, model, and policy details are unavailable from the runtime.')).toBeVisible()
  await prompt.fill('Inspect the workspace')
  await expect(page.getByRole('button', { name: 'Start task', exact: true })).toBeEnabled()
  await page.screenshot({ path: '/home/ryltsevmg/runne/worktree-logs/dx1-desktop/composer-mock.png' })
  await page.getByRole('button', { name: 'Start task', exact: true }).click()

  await expect(page).toHaveURL(new RegExp(`/task-runs/${taskRunId}$`))
  await expect(page.getByRole('heading', { name: 'completed' })).toBeVisible()
  await expect(page.getByLabel('Task run timeline')).toContainText('completed')
  await expect(page.evaluate(() => localStorage.getItem('mock-managed-token'))).resolves.toBe(recoveryToken)
})

test('reload reconciles an uncertain start using its original token without a second submission', async ({ page }) => {
  await installManagedComposerAdapter(page, true)
  await page.goto(`/workspaces/${managedWorkspace.workspaceId}`)
  await page.getByRole('textbox', { name: 'Task' }).fill('Keep this intent identity')
  await page.getByRole('button', { name: 'Start task', exact: true }).click()
  await expect(page.getByText('The start result is uncertain', { exact: false })).toBeVisible()
  await expect.poll(() => page.evaluate(() => localStorage.getItem('mock-managed-starts'))).toBe('1')

  await page.reload()
  await expect(page.getByText('The start result is uncertain', { exact: false })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Check request status' })).toBeVisible()
  await expect(page.getByRole('textbox', { name: 'Task' })).toHaveValue('')
  await expect.poll(() => page.evaluate(() => localStorage.getItem('mock-managed-starts'))).toBe('1')
  await expect(page.evaluate(() => localStorage.getItem('mock-managed-recovered-token'))).resolves.toBe(recoveryToken)
  await expect(page.evaluate(() => localStorage.getItem('mock-managed-token'))).resolves.toBe(recoveryToken)
})
