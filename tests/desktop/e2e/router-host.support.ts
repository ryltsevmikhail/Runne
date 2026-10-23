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
  unresolved: number
  settled: number
  barriers: { command: string; workspaceId: unknown; phase: 'held' | 'released' | 'settled' }[]
  drafts: Record<string, import('../../../apps/desktop/src/entities/task-run/api/managed-task-draft').ManagedTaskDraft>
  release(): void
}
declare global { interface Window { __hostFixture: HostControl } }
export const secondWorkspace = { ...workspace, workspaceId: '01890e00-0000-7000-8000-000000000020', displayName: 'second workspace' }

export async function installHostControl(page: Page, options: { pending?: ActivationTarget | Record<string, unknown>; holdConnect?: boolean; durable?: boolean; holdDraft?: 'load'; holdWorkspace?: boolean; rich?: boolean } = {}): Promise<void> {
  await installRouterAdapter(page)
  await page.addInitScript(({ options, workspace, secondWorkspace }) => {
    const host = window.__TAURI_INTERNALS__
    const invoke = host.invoke.bind(host)
    const releases: (() => void)[] = []
    const control: HostControl = {
      state: 'live', calls: [], failures: [], held: 0, unresolved: 0, settled: 0, barriers: [],
      drafts: {
        [workspace.workspaceId]: { revision: 3, prompt: 'saved A private draft', scopeToken: 'a'.repeat(64) },
        [secondWorkspace.workspaceId]: { revision: 7, prompt: 'saved B private draft', scopeToken: 'b'.repeat(64) },
      },
      release() { releases.splice(0).forEach(resolve => resolve()) },
    }
    const hold = async (command: string, workspaceId?: unknown) => {
      control.held += 1; control.unresolved += 1
      const mark = (phase: 'held' | 'released' | 'settled') => {
        const barrier = { command, workspaceId: workspaceId ?? null, phase }
        control.barriers.push(barrier)
        console.debug('runne-router-barrier ' + JSON.stringify(barrier))
      }
      mark('held')
      await new Promise<void>(resolve => releases.push(() => { mark('released'); resolve() }))
      control.unresolved -= 1; control.settled += 1; mark('settled')
    }
    ;window.__hostFixture = control
    host.invoke = async (command, args) => {
      control.calls.push({ command, args })
      const id = control.calls.length
      // Trace capture survives reload; the in-page attachment intentionally describes only its document.
      const record = (phase: string, value: unknown) => console.debug('runne-router-fixture ' + JSON.stringify({ phase, id, document: performance.timeOrigin, command, value }))
      record('invoke', args)
      const dispatch = async () => {
        if (command === 'connect_runtime' && options.holdConnect) { await hold(command); return 'live' }
        if (options.durable && command === 'prepare_managed_task_run') {
          if (args?.projectId !== workspace.projectId || typeof args.workspaceId !== 'string' || !control.drafts[args.workspaceId]) throw new Error('unexpected draft preflight scope')
          const unavailable = { status: 'unavailable', reason: 'runtime_projection_missing' } as const
          return {
            status: 'ready', generation: 1, projectId: workspace.projectId, workspaceId: args.workspaceId,
            conversationId: '01890e00-0000-7000-8000-000000000003', canStart: true, startUnavailableReason: null,
            authority: { provider: unavailable, model: unavailable, policy: unavailable }, draftPolicy: 'protected_restart',
            recoveryToken: '01890e00-0000-7000-8000-000000000004',
          } satisfies import('../../../apps/desktop/src/entities/task-run/api/managed-task-run').ManagedTaskRunPreflight
        }
        if (options.durable && (command === 'load_managed_task_draft' || command === 'save_managed_task_draft')) {
          if (args?.projectId !== workspace.projectId || typeof args.workspaceId !== 'string' || !control.drafts[args.workspaceId]) throw new Error('unexpected draft persistence scope')
          const current = control.drafts[args.workspaceId]
          if (current === undefined) throw new Error('missing fixture draft')
          if (command === 'save_managed_task_draft') {
            if (args.scopeToken !== current.scopeToken || args.expectedRevision !== current.revision || typeof args.prompt !== 'string' || !args.prompt) throw new Error('invalid fixture draft write')
            control.drafts[args.workspaceId] = { revision: current.revision + 1, prompt: args.prompt, scopeToken: current.scopeToken }
          }
          const response = { ...control.drafts[args.workspaceId] }
          if (args.workspaceId === workspace.workspaceId && command === `${options.holdDraft}_managed_task_draft`) await hold(command, args.workspaceId)
          return response
        }
        if (command === 'get_pending_external_activation') return options.pending ?? null
        if (command === 'get_bootstrap') return { theme: 'dark', runtimeMode: 'bundled', runtime: control.state, runtimeLifecycle: control.state === 'live' ? 'ready' : 'restarting', runtimeFailure: null } satisfies BootstrapState
        if (command === 'get_canonical_workspace') {
          if (args?.workspaceId === secondWorkspace.workspaceId) return secondWorkspace
          if (args?.workspaceId === workspace.workspaceId && options.holdWorkspace) {
            await hold(command, args.workspaceId)
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
      try {
        const value = await dispatch()
        record('result', value)
        return value
      }
      catch (error) {
        record('failure', error instanceof Error ? error.message : String(error))
        control.failures.push(error instanceof Error ? error.message : String(error))
        throw error
      }
    }
  }, { options, workspace, secondWorkspace })
}
export const hostObservations = (page: Page) => page.evaluate(() => {
  const { calls, failures, held, state, unresolved, settled, barriers, drafts } = window.__hostFixture
  return { calls, failures, held, state, unresolved, settled, barriers, drafts }
})
export const setRuntime = (page: Page, state: RuntimeConnectionState) => page.evaluate(state => { window.__hostFixture.state = state }, state)
export const releaseWorkspace = (page: Page) => page.evaluate(() => window.__hostFixture.release())
