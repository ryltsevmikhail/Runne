import { type Page } from '@playwright/test'

export const workspace = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

export async function installDesktopAdapter(page: Page): Promise<void> {
  await page.addInitScript(({ currentWorkspace }) => {
    type TauriInternals = {
      invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown>
      transformCallback: () => number
      unregisterCallback: () => void
      convertFileSrc: (path: string) => string
    }
    type ReplayWindow = Window & { __TAURI_INTERNALS__: TauriInternals }

    ;(globalThis as typeof globalThis & { isTauri: boolean }).isTauri = true
    ;(window as ReplayWindow).__TAURI_INTERNALS__ = {
      transformCallback() {
        return 1
      },
      unregisterCallback() {},
      convertFileSrc(path) {
        return path
      },
      async invoke(command, args) {
        switch (command) {
          case 'get_bootstrap':
            return {
              theme: 'dark',
              runtimeMode: 'bundled',
              runtime: 'live',
              runtimeLifecycle: 'ready',
              runtimeFailure: null,
            }
          case 'connect_runtime':
            return 'live'
          case 'get_workspace':
            return args?.workspaceId === currentWorkspace.workspaceId
              ? currentWorkspace
              : null
          case 'set_theme':
            return null
          default:
            throw new Error(`unsupported test command: ${command}`)
        }
      },
    }
  }, { currentWorkspace: workspace })
}
