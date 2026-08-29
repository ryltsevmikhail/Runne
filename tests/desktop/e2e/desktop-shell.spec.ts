import { expect, test } from '@playwright/test'

test('desktop shell supports navigation, themes and collapsed sidebar', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible()
  await expect(page.getByText('External runtime')).toBeVisible()

  await page.getByLabel('Use light theme').click()
  await expect(page.locator('.app-shell')).toHaveAttribute('data-theme', 'light')

  await page.getByLabel('Collapse sidebar').click()
  await expect(page.locator('aside')).toHaveClass(/sidebar--collapsed/)

  await page.getByRole('button', { name: 'Settings' }).click()
  await expect(page.getByRole('heading', { name: 'Runtime' })).toBeVisible()
})

test.describe('narrow desktop shell', () => {
  test.use({ viewport: { width: 1023, height: 900 } })

  test('keeps the sidebar rail navigable and keyboard-expandable', async ({ page }) => {
    await page.goto('/')

    const rail = page.locator('aside.sidebar')
    const projects = page.getByRole('button', { name: 'Projects' })
    const settings = page.getByRole('button', { name: 'Settings' })
    const collapse = page.getByLabel('Collapse sidebar')

    await expect(rail).toHaveCSS('width', '48px')
    await expect(projects).toBeVisible()
    await expect(projects.locator('svg')).toBeVisible()
    await expect(settings).toBeVisible()
    await expect(settings.locator('svg')).toBeVisible()
    expect(await rail.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true)

    await expect(collapse).toBeVisible()
    await collapse.focus()
    await page.keyboard.press('Enter')
    await expect(rail).toHaveClass(/sidebar--collapsed/)

    const expand = page.getByLabel('Expand sidebar')
    await expect(expand).toBeVisible()
    await expand.focus()
    await page.keyboard.press('Enter')
    await expect(rail).not.toHaveClass(/sidebar--collapsed/)

    await settings.click()
    await expect(page.getByRole('heading', { name: 'Runtime' })).toBeVisible()
  })
})
