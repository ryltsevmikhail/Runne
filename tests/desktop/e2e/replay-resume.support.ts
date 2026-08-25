import { type Page } from '@playwright/test'

export const workspace = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  version: 1,
  open: true,
} as const

export const project = {
  projectId: workspace.projectId,
  displayName: 'gocode-ui',
  version: 1,
  archived: false,
} as const

export async function installDesktopAdapter(page: Page): Promise<void> {
  await page.addInitScript(({ currentProject, currentWorkspace }) => {
    type TauriInternals = {
      invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown>
      transformCallback: () => number
      unregisterCallback: () => void
      convertFileSrc: (path: string) => string
    }
    type ReplayWindow = Window & { __TAURI_INTERNALS__: TauriInternals }

    ;(globalThis as typeof globalThis & { isTauri: boolean }).isTauri = true
    let workspaceCreated = false
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
          case 'acquire_renderer_generation':
            return 1
          case 'request_directory_selection':
            return { reference: 'a'.repeat(64) }
          case 'create_runtime_project':
            return { projectId: currentProject.projectId, newVersion: 1 }
          case 'prepare_selected_workspace':
            return { reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' } }
          case 'open_selected_workspace':
            return null
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
          case 'get_canonical_workspace':
            return args?.workspaceId === currentWorkspace.workspaceId
              ? currentWorkspace
              : null
          case 'get_canonical_project':
            return args?.projectId === currentProject.projectId
              ? { project: currentProject, workspaces: workspaceCreated ? [currentWorkspace] : [] }
              : null
          case 'create_runtime_workspace':
            workspaceCreated = true
            return { workspaceId: currentWorkspace.workspaceId, newVersion: 1 }
          case 'set_theme':
            return null
          default:
            throw new Error(`unsupported test command: ${command}`)
        }
      },
    }
  }, { currentProject: project, currentWorkspace: workspace })
}
