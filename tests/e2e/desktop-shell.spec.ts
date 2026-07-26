import { expect, test } from '@playwright/test'

test('desktop shell supports navigation, themes and collapsed sidebar', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible()
  await expect(page.getByText('Runtime offline')).toBeVisible()

  await page.getByLabel('Use light theme').click()
  await expect(page.locator('.app-shell')).toHaveAttribute('data-theme', 'light')

  await page.getByLabel('Collapse sidebar').click()
  await expect(page.locator('aside')).toHaveClass(/sidebar--collapsed/)

  await page.getByRole('link', { name: 'Settings' }).click()
  await expect(page.getByRole('heading', { name: 'Runtime' })).toBeVisible()
})
