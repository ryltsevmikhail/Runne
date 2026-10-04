import { expect, test } from '@playwright/test'

test('shows a static startup message when the loader cannot load', async ({ page }) => {
  await page.route('**/src/app/startup.ts*', route => route.abort())
  await page.goto('/')

  const status = page.getByRole('alert')
  await expect(status.getByRole('heading', { name: 'Runne couldn’t start' })).toBeVisible()
  await expect(status.getByText('The app has not loaded yet. Refresh the page to try again.'))
    .toBeVisible()
  await expect(status.getByRole('link', { name: 'Refresh Runne' })).toHaveAttribute('href', '/')
})

test('shows a safe startup error when the app entry module fails', async ({ page }) => {
  await page.route('**/src/main.ts*', route => route.abort())
  await page.goto('/')

  const status = page.getByRole('alert')
  await expect(status.getByRole('heading', { name: 'Runne couldn’t start' })).toBeVisible()
  await expect(status.getByText('Part of the app failed to load. Refresh the page to try again.'))
    .toBeVisible()
  await expect(status.getByRole('link', { name: 'Refresh Runne' })).toHaveAttribute('href', '/')
  await expect(status).not.toContainText(/Error:|main\.ts|stack|token|key/i)
})

test('removes the startup message after the app mounts', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible()
  await expect(page.locator('#startup-status')).toHaveCount(0)
})
