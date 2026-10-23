import { expect, type Page, type TestInfo } from '@playwright/test'
type RouteLocationRaw = string | { name: string; params?: Record<string, string>; query?: Record<string, string | null | string[]>; hash?: string }
import { installManagedComposerAdapter } from './managed-task-composer.support'

export interface RouteSnapshot {
  name: string | null
  fullPath: string
  params: Record<string, string | string[]>
  query: Record<string, string | null | (string | null)[]>
  hash: string
}
export interface NavigationResult { type: number | null; rejected: boolean; message?: string }
interface NavigationPort {
  snapshot(): RouteSnapshot
  navigate(target: RouteLocationRaw, replace?: boolean): Promise<NavigationResult>
  guard(mode: 'abort' | 'throw' | 'defer' | 'redirect' | 'loop'): void
  clear(): void
  release(): void
  observations(): { errors: string[]; entered: number; hops: number }
}
// Test compilation only: these are installed by the existing IPC adapter and intercepted entry.
declare global {
  interface Window {
    __routerFixture: NavigationPort
    __TAURI_INTERNALS__: {
      invoke(command: string, args?: Record<string, unknown>): Promise<unknown>
      transformCallback(): number
      unregisterCallback(): void
      convertFileSrc(path: string): string
    }
  }
}

// Only fixture-main responses carry this port; ordinary entry rows do not install it.
export async function installRouterPort(page: Page): Promise<void> {
  await page.route('**/src/main.ts', async route => {
    const response = await route.fetch()
    const original = await response.text()
    expect(original).toContain('const router = createRouter(')
    const instrumentation = `
let removeFixtureGuard = () => {};
let releaseFixtureGuard = () => {};
let entered = 0, hops = 0;
const errors = [];
router.onError(error => errors.push(error.message));
window.__routerFixture = {
  snapshot() {
    const { name, fullPath, params, query, hash } = router.currentRoute.value;
    return { name: name === undefined ? null : String(name), fullPath, params, query, hash };
  },
  async navigate(target, replace = false) {
    try {
      const result = await router[replace ? 'replace' : 'push'](target);
      return { type: result?.type ?? null, rejected: false };
    } catch (error) { return { type: null, rejected: true, message: error.message }; }
  },
  clear() { removeFixtureGuard(); removeFixtureGuard = () => {}; },
  release() { releaseFixtureGuard(); },
  observations() { return { errors: [...errors], entered, hops }; },
  guard(mode) {
    removeFixtureGuard(); entered = 0; hops = 0;
    removeFixtureGuard = router.beforeEach(async to => {
      if (mode === 'loop' && (to.name === 'settings' || to.name === 'recovery')) {
        hops += 1;
        return hops >= 8 ? false : { name: to.name === 'settings' ? 'recovery' : 'settings' };
      }
      if (to.name !== 'recovery') return;
      entered += 1;
      if (mode === 'abort') return false;
      if (mode === 'throw') throw new Error('bounded fixture guard failure');
      if (mode === 'redirect') return { name: 'settings' };
      if (mode === 'defer') await new Promise(resolve => { releaseFixtureGuard = resolve; });
    });
  }
};`
    await route.fulfill({ response, body: `${original}\n${instrumentation}` })
  })
}

export const snapshot = (page: Page) => page.evaluate(() => window.__routerFixture.snapshot())
export const navigate = (page: Page, target: RouteLocationRaw, replace = false) =>
  page.evaluate(({ target, replace }) => window.__routerFixture.navigate(target, replace), { target, replace })
export const guard = (page: Page, mode: Parameters<NavigationPort['guard']>[0]) =>
  page.evaluate(mode => window.__routerFixture.guard(mode), mode)
export const clearGuard = (page: Page) => page.evaluate(() => window.__routerFixture.clear())
export const releaseGuard = (page: Page) => page.evaluate(() => window.__routerFixture.release())
export const observations = (page: Page) => page.evaluate(() => window.__routerFixture.observations())

export async function attachRoutingEvidence(page: Page, info: TestInfo): Promise<void> {
  const evidence = await page.evaluate(() => {
    const target = window as Window & { __routerFixture?: NavigationPort; __hostFixture?: { state: string; calls: unknown[]; failures: string[]; held: number } }
    return {
      url: location.href, route: target.__routerFixture?.snapshot() ?? null,
      guards: target.__routerFixture?.observations() ?? null,
      host: target.__hostFixture ? { state: target.__hostFixture.state, calls: target.__hostFixture.calls, failures: target.__hostFixture.failures, held: target.__hostFixture.held } : null,
      scrollRestoration: history.scrollRestoration,
    }
  })
  await info.attach('routing-fixture-evidence', { body: JSON.stringify(evidence, null, 2), contentType: 'application/json' })
}

export async function installRouterAdapter(page: Page): Promise<void> {
  await installManagedComposerAdapter(page)
  await page.addInitScript(() => {
    const host = window.__TAURI_INTERNALS__
    const invoke = host.invoke.bind(host)
    host.invoke = async (command, args) => {
      if (command === 'list_managed_task_runs') return { status: 'available', taskRuns: [] }
      if (command === 'list_pending_approvals') return []
      if (command === 'get_managed_attention_snapshot') return { status: 'available', complete: true, items: [] }
      if (command === 'sync_notifications') return { shown: 0, pending: 0 }
      return invoke(command, args)
    }
  })
}
