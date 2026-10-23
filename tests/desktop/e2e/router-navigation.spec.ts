import { expect, test } from '@playwright/test'
import { managedWorkspace as workspace, taskRunId } from './managed-task-composer.support'
import { attachRoutingEvidence, clearGuard, guard, installRouterPort, navigate, observations, releaseGuard, snapshot } from './router-navigation.support'
import { installHostControl } from './router-host.support'

test.afterEach(async ({ page }, info) => { await attachRoutingEvidence(page, info) })

const unknown = '01890e00-0000-7000-8000-000000000099'
const processId = '01890e00-0000-7000-8000-000000000003'
const deepRows = [
  { label: 'workspace process', path: `/workspaces/${workspace.workspaceId}?processId=${processId}`, selector: '.workspace-page', text: 'gocode-ui', active: 'Projects' },
  { label: 'TaskRun', path: `/task-runs/${taskRunId}`, selector: 'main', text: 'Task run', active: 'Task runs' },
  { label: 'recovery', path: '/recovery', selector: '.recovery-page', text: 'Project recovery', active: 'Projects' },
  { label: 'diagnostics', path: '/settings/diagnostics', selector: 'main', text: 'Diagnostics', active: 'Settings' },
  { label: 'project redirect', path: `/projects/${workspace.projectId}?discard=yes#details`, destination: `/?project=${workspace.projectId}#details`, selector: 'main', text: 'Projects', active: 'Projects' },
  { label: 'unknown workspace', path: `/workspaces/${unknown}`, selector: 'main', text: 'Project unavailable', active: 'Projects' },
]
for (const row of deepRows) {
  test(`ordinary entry preserves ${row.label} through reload`, async ({ page }) => {
    await installHostControl(page)
    await page.goto(row.path)
    for (const reload of [false, true]) {
      if (reload) await page.reload()
      await expect(page.locator(row.selector)).toContainText(row.text)
      await expect(page).toHaveURL(`http://127.0.0.1:1420${row.destination ?? row.path}`)
      await expect(page.getByRole('button', { name: row.active, exact: true })).toHaveClass(/active/)
      await expect(page.locator('body')).not.toContainText('/workspace/gocode-ui')
      expect(await page.evaluate(() => '__routerFixture' in window)).toBe(false)
    }
  })
}

test.describe('ordinary real Router test-only guard fixture', () => {
  test.beforeEach(async ({ page }) => {
    await installHostControl(page)
    await installRouterPort(page)
    await page.goto(`/?project=${workspace.projectId}`)
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible()
  })

  test('browser history follows sidebar navigation, replace, duplicate and forward-branch invalidation', async ({ page }) => {
    const selected = `/?project=${workspace.projectId}`
    await page.getByRole('button', { name: 'Open workspace gocode-ui', exact: true }).click()
    await expect(page).toHaveURL(`http://127.0.0.1:1420/workspaces/${workspace.workspaceId}`)
    await page.getByRole('button', { name: 'Settings', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Runtime', exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Task runs', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Task runs', exact: true })).toBeVisible()
    await page.goBack()
    await expect(page).toHaveURL('http://127.0.0.1:1420/settings/runtimes')
    await page.goBack()
    await expect(page.getByRole('heading', { name: workspace.displayName })).toBeVisible()
    await page.goForward()
    await expect(page).toHaveURL('http://127.0.0.1:1420/settings/runtimes')
    const length = await page.evaluate(() => history.length)
    expect(await navigate(page, '/settings/diagnostics', true)).toEqual({ type: null, rejected: false })
    expect(await page.evaluate(() => history.length)).toBe(length)
    expect(await navigate(page, '/settings/diagnostics')).toEqual({ type: 16, rejected: false })
    expect(await page.evaluate(() => history.length)).toBe(length)
    await page.goBack()
    await expect(page).toHaveURL(`http://127.0.0.1:1420/workspaces/${workspace.workspaceId}`)
    await navigate(page, '/recovery')
    await page.goForward()
    await expect(page).toHaveURL('http://127.0.0.1:1420/recovery')
    expect((await snapshot(page)).name).toBe('recovery')
    await page.goBack()
    await page.goBack()
    await expect(page).toHaveURL(`http://127.0.0.1:1420${selected}`)
    expect((await snapshot(page)).query).toEqual({ project: workspace.projectId })
  })

  test('ordinary encoded query shapes and reserved params preserve the app boundary', async ({ page }) => {
    const query = { processId, text: '雪 +%/?#', repeated: ['one', 'two'], flag: null, empty: '' }
    expect(await navigate(page, { name: 'workspace', params: { workspaceId: workspace.workspaceId }, query, hash: '#details' })).toEqual({ type: null, rejected: false })
    expect((await snapshot(page)).query).toEqual(query)
    expect(new URL(page.url()).searchParams.get('text')).toBe('雪 +%/?#')
    expect(new URL(page.url()).searchParams.getAll('repeated')).toEqual(['one', 'two'])
    await expect(page.getByRole('heading', { name: workspace.displayName })).toBeVisible()
    await navigate(page, { name: 'workspace', params: { workspaceId: 'not/a+canonical%id' } })
    await expect(page).toHaveURL('http://127.0.0.1:1420/workspaces/not%2Fa+canonical%25id')
    await expect(page.getByRole('alert').filter({ hasText: 'Project unavailable' })).toBeVisible()
    await expect(page.getByRole('textbox', { name: 'Message', exact: true })).toHaveCount(0)
    await navigate(page, `/projects/${workspace.projectId}?drop=old#details`)
    expect((await snapshot(page)).fullPath).toBe(`/?project=${workspace.projectId}#details`)
  })

  for (const mode of ['abort', 'throw', 'redirect', 'loop'] as const) {
    test(`settles ${mode} guard and permits the next navigation`, async ({ page }) => {
      await guard(page, mode)
      const result = await navigate(page, mode === 'loop' ? '/settings' : '/recovery')
      expect(result).toEqual(mode === 'throw'
        ? { type: null, rejected: true, message: 'bounded fixture guard failure' }
        : { type: mode === 'redirect' ? null : 4, rejected: false })
      const observed = await observations(page)
      expect(observed.errors).toEqual(mode === 'throw' ? ['bounded fixture guard failure'] : [])
      expect(observed.hops).toBe(mode === 'loop' ? 8 : 0)
      expect((await snapshot(page)).name).toBe(mode === 'redirect' ? 'settings' : 'projects')
      await clearGuard(page)
      expect(await navigate(page, '/recovery')).toEqual({ type: null, rejected: false })
      await expect(page.getByRole('heading', { name: 'Project recovery', exact: true })).toBeVisible()
    })
  }

  test('a competing navigation cancels a deferred guard without an unhandled rejection', async ({ page }) => {
    await guard(page, 'defer')
    const pending = navigate(page, '/recovery')
    await expect.poll(async () => (await observations(page)).entered).toBe(1)
    await navigate(page, '/settings')
    await releaseGuard(page)
    expect(await pending).toEqual({ type: 8, rejected: false })
    expect((await snapshot(page)).name).toBe('settings')
    expect((await observations(page)).errors).toEqual([])
    await clearGuard(page)
    await navigate(page, '/recovery')
    await expect(page.getByRole('heading', { name: 'Project recovery', exact: true })).toBeVisible()
  })
})
