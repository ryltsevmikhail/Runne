import { expect, test, type Page } from '@playwright/test'
import { managedWorkspace as workspace } from './managed-task-composer.support'
import { hostObservations, installHostControl } from './router-host.support'
import { attachRoutingEvidence, installRouterPort, navigate, snapshot } from './router-navigation.support'

const processId = '01890e00-0000-7000-8000-000000000003'
const path = `/workspaces/${workspace.workspaceId}`
const containers = ['main.workspace', '.sidebar-projects', '.workspace-frame__conversation', '.terminal-panel__output']
const offsets = (page: Page) => page.evaluate(selectors => Object.fromEntries(selectors.map(selector => {
  const node = document.querySelector<HTMLElement>(selector)
  if (!node) throw new Error(`Missing actual app scroll container: ${selector}`)
  return [selector, { top: node.scrollTop, height: node.clientHeight, scrollHeight: node.scrollHeight, overflow: getComputedStyle(node).overflowY }]
})), containers)

test.afterEach(async ({ page }, info) => { await attachRoutingEvidence(page, info) })

for (const row of [
  { label: 'canonical scalar', query: `processId=${processId}`, reads: 1, open: true },
  { label: 'repeated IDs', query: `processId=${processId}&processId=${processId}`, reads: 0, open: false },
  { label: 'malformed ID', query: 'processId=not-canonical', reads: 0, open: false },
]) {
  test(`workspace process query uses ${row.label} without broadening runtime identity`, async ({ page }) => {
    await installHostControl(page)
    await page.goto(`${path}?${row.query}`)
    await expect(page.getByRole('heading', { name: workspace.displayName })).toBeVisible()
    await expect(page.locator('.workspace-terminal-disclosure')).toHaveJSProperty('open', row.open)
    if (row.reads) await expect.poll(async () => (await hostObservations(page)).calls.filter(call => call.command === 'read_process_output').length).toBe(row.reads)
    const reads = (await hostObservations(page)).calls.filter(call => call.command === 'read_process_output')
    expect(reads).toHaveLength(row.reads)
    if (reads.length) expect(reads[0]?.args).toEqual({ processId, afterSequence: 0, limit: 64 })
    expect((await hostObservations(page)).failures).toEqual([])
  })
}

test('actual application container offsets survive same-view push/hash/back/forward/replace without custom scrollBehavior', async ({ page }, info) => {
  await page.setViewportSize({ width: 1440, height: 400 })
  await installHostControl(page, { rich: true })
  await installRouterPort(page)
  const initialPath = `${path}?processId=${processId}`
  await page.goto(initialPath)
  await expect(page.locator('.terminal-panel__output')).toContainText('synthetic public output')
  await expect(page.getByRole('button', { name: 'Open project Fixture project 39', exact: true })).toHaveCount(1)
  const measurements: unknown[] = [{ phase: 'initial', containers: await offsets(page) }]
  await page.evaluate(selectors => {
    for (const selector of selectors) {
      const node = document.querySelector<HTMLElement>(selector)
      if (node) node.scrollTop = 60
    }
  }, containers)
  const scrolled = await offsets(page)
  await info.attach('actual-scroll-before-navigation', { body: JSON.stringify(scrolled, null, 2), contentType: 'application/json' })
  expect(scrolled['main.workspace']!.top).toBe(60)
  expect(scrolled['.sidebar-projects']!.top).toBe(60)
  // This real layout expands the conversation frame; the nested terminal pane actually scrolls.
  expect(scrolled['.workspace-frame__conversation']!.top).toBe(0)
  expect(scrolled['.workspace-frame__conversation']!.height).toBe(scrolled['.workspace-frame__conversation']!.scrollHeight)
  expect(scrolled['.terminal-panel__output']!.top).toBe(60)
  const restoration = await page.evaluate(() => history.scrollRestoration)
  measurements.push({ phase: 'scrolled', containers: scrolled, restoration })
  await navigate(page, `${initialPath}#details`)
  expect(await offsets(page)).toEqual(scrolled)
  measurements.push({ phase: 'push-hash', containers: await offsets(page) })
  await navigate(page, `${initialPath}#replacement`, true)
  expect(await offsets(page)).toEqual(scrolled)
  measurements.push({ phase: 'replace-hash', containers: await offsets(page) })
  await page.goBack()
  await expect(page).toHaveURL(`http://127.0.0.1:1420${initialPath}`)
  expect(await offsets(page)).toEqual(scrolled)
  measurements.push({ phase: 'back', containers: await offsets(page) })
  await page.goForward()
  await expect(page).toHaveURL(`http://127.0.0.1:1420${initialPath}#replacement`)
  expect(await offsets(page)).toEqual(scrolled)
  measurements.push({ phase: 'forward', containers: await offsets(page) })
  expect(await page.evaluate(() => history.scrollRestoration)).toBe(restoration)
  expect((await snapshot(page)).params.workspaceId).toBe(workspace.workspaceId)
  await info.attach('actual-app-scroll-measurements', { body: JSON.stringify(measurements, null, 2), contentType: 'application/json' })
})
