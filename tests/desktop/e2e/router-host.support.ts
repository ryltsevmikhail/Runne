import type { Page } from '@playwright/test'
import type { BootstrapState, RuntimeConnectionState } from '../../../apps/desktop/src/shared/api/platform/bootstrap'
import type { ActivationTarget } from '../../../apps/desktop/src/shared/api/platform/external-activation'
import { managedWorkspace as workspace } from './managed-task-composer.support'
import { installRouterAdapter } from './router-navigation.support'

interface HostControl {
  state: RuntimeConnectionState
  calls: { command: string; args: Record<string, unknown> | undefined }[]
  failures: string[]
  held: number
  release(): void
}
declare global { interface Window { __hostFixture: HostControl } }
export const secondWorkspace = { ...workspace, workspaceId: '01890e00-0000-7000-8000-000000000020', displayName: 'second workspace' }

export async function installHostControl(page: Page, options: { pending?: ActivationTarget | Record<string, unknown>; holdWorkspace?: boolean; rich?: boolean } = {}): Promise<void> {
  await installRouterAdapter(page)
  await page.addInitScript(({ options, workspace, secondWorkspace }) => {
    const host = window.__TAURI_INTERNALS__
    const invoke = host.invoke.bind(host)
    const releases: (() => void)[] = []
    const control: HostControl = { state: 'live', calls: [], failures: [], held: 0, release() { releases.splice(0).forEach(resolve => resolve()) } }
    ;window.__hostFixture = control
    host.invoke = async (command, args) => {
      control.calls.push({ command, args })
      try {
        if (command === 'get_pending_external_activation') return options.pending ?? null
        if (command === 'get_bootstrap') return { theme: 'dark', runtimeMode: 'bundled', runtime: control.state, runtimeLifecycle: control.state === 'live' ? 'ready' : 'restarting', runtimeFailure: null } satisfies BootstrapState
        if (command === 'get_canonical_workspace') {
          if (args?.workspaceId === secondWorkspace.workspaceId) return secondWorkspace
          if (args?.workspaceId === workspace.workspaceId && options.holdWorkspace) {
            control.held += 1
            await new Promise<void>(resolve => releases.push(resolve))
            return workspace
          }
        }
        if (command === 'get_canonical_project' && args?.projectId === workspace.projectId) return {
          project: { projectId: workspace.projectId, displayName: 'gocode-ui', version: 1, archived: false }, workspaces: [workspace, secondWorkspace],
        }
        if (command === 'get_permission_mode_status') return {
          selectedMode: 'ask_always', effective: { state: 'notReady', reason: 'native_containment' },
          authorizationRevision: 4, presetVersion: 1, managedPolicyVersion: 1,
          pendingApprovalIds: [], containment: null, networkState: 'unavailable', expiresAtUnixMs: null,
        }
        if (command === 'list_canonical_projects' && options.rich) return Array.from({ length: 40 }, (_, index) => ({
          projectId: index === 0 ? workspace.projectId : `01890e00-0000-7000-8000-${String(index + 100).padStart(12, '0')}`,
          displayName: index === 0 ? 'gocode-ui' : `Fixture project ${index}`, version: 1, archived: false,
        }))
        if (command === 'read_process_output') {
          if (args?.afterSequence !== 0 || args?.limit !== 64) throw new Error('unexpected process cursor fixture')
          return { chunks: options.rich ? [{ sequence: 1, stream: 'stdout', text: 'synthetic public output\n'.repeat(160) }] : [] }
        }
        return await invoke(command, args)
      }
      catch (error) {
        control.failures.push(error instanceof Error ? error.message : String(error))
        throw error
      }
    }
  }, { options, workspace, secondWorkspace })
}
export const hostObservations = (page: Page) => page.evaluate(() => {
  const { calls, failures, held, state } = window.__hostFixture
  return { calls, failures, held, state }
})
export const setRuntime = (page: Page, state: RuntimeConnectionState) => page.evaluate(state => { window.__hostFixture.state = state }, state)
export const releaseWorkspace = (page: Page) => page.evaluate(() => window.__hostFixture.release())
