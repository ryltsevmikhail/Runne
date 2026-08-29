import { expect, test } from '@playwright/test'

function relativeLuminance(color: string): number {
  const channels = color.match(/[\d.]+/g)?.slice(0, 3).map(Number)
  if (channels === undefined || channels.length !== 3) {
    throw new Error(`Expected an RGB color, received ${color}`)
  }
  const normalized = channels.map(channel => channel / 255)
  const linear = normalized.map(channel => channel <= .04045
    ? channel / 12.92
    : ((channel + .055) / 1.055) ** 2.4)
  return .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2]
}

function contrastRatio(background: string, foreground: string): number {
  const [lighter, darker] = [relativeLuminance(background), relativeLuminance(foreground)]
    .sort((left, right) => right - left)
  return (lighter + .05) / (darker + .05)
}

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

test('terminal output remains readable in the light theme', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Use light theme').click()

  const terminal = page.locator('.app-shell').evaluateHandle(shell => {
    const panel = document.createElement('section')
    panel.className = 'terminal-panel'
    const output = document.createElement('pre')
    output.className = 'terminal-panel__output'
    output.textContent = 'runtime-owned output'
    panel.append(output)
    shell.append(panel)
    return panel
  })
  const colors = await (await terminal).evaluate(panel => {
    const output = panel.querySelector('.terminal-panel__output')
    const shell = document.querySelector('.app-shell')
    if (output === null || shell === null) throw new Error('Terminal surface was not installed')
    return {
      page: getComputedStyle(shell).backgroundColor,
      terminal: getComputedStyle(panel).backgroundColor,
      output: getComputedStyle(output).color,
    }
  })

  expect(colors.terminal).not.toBe(colors.page)
  expect(contrastRatio(colors.terminal, colors.output)).toBeGreaterThanOrEqual(4.5)
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
