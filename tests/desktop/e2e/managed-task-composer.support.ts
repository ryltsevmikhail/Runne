import type { Page } from '@playwright/test'

export const managedWorkspace = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui', version: 1, open: true,
} as const
export const conversationId = '01890e00-0000-7000-8000-000000000003'
export const recoveryToken = '01890e00-0000-7000-8000-000000000004'
export const taskRunId = '01890e00-0000-7000-8000-000000000010'
const project = { projectId: managedWorkspace.projectId, displayName: managedWorkspace.displayName, version: 1, archived: false }
const unavailable = { status: 'unavailable', reason: 'runtime_projection_missing' }
const authority = { provider: unavailable, model: unavailable, policy: unavailable }
const conversation = { conversationId, projectionRevision: 1, streamVersion: 1, messages: [], recovery: 'live' }
const timeline = {
  taskRunId, projectionRevision: 1, streamVersion: 2, state: 'succeeded', activeAttemptId: null, terminal: 'success',
  entries: [{ eventId: '01890e00-0000-7000-8000-000000000011', sequence: 1, committedAt: 1, kind: 'completed', attemptId: null }], recovery: 'live',
}

export async function installManagedComposerAdapter(page: Page, uncertain = false): Promise<void> {
  await page.addInitScript(({ project, workspace, conversation, conversationId, authority, recoveryToken, taskRunId, timeline, uncertain }) => {
    type Host = { invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown>, transformCallback: () => number, unregisterCallback: () => void, convertFileSrc: (path: string) => string }
    ;(globalThis as typeof globalThis & { isTauri: boolean }).isTauri = true
    ;(window as Window & { __TAURI_INTERNALS__: Host }).__TAURI_INTERNALS__ = {
      transformCallback: () => 1, unregisterCallback: () => {}, convertFileSrc: path => path,
      async invoke(command, args) {
        switch (command) {
          case 'acquire_renderer_generation': return 1
          case 'get_bootstrap': return { theme: 'dark', runtimeMode: 'bundled', runtime: 'live', runtimeLifecycle: 'ready', runtimeFailure: null }
          case 'get_locale': return { locale: 'en' }
          case 'get_pending_external_activation': return null
          case 'plugin:event|listen': return 1
          case 'plugin:event|unlisten': return null
          case 'connect_runtime': return 'live'
          case 'get_canonical_workspace': return args?.workspaceId === workspace.workspaceId ? workspace : null
          case 'list_canonical_projects': return [project]
          case 'get_canonical_project': return args?.projectId === project.projectId ? { project, workspaces: [workspace] } : null
          case 'list_workspace_files': return { items: [] }
          case 'list_workspace_changes': return { items: [] }
          case 'open_workspace_conversation':
          case 'resync_workspace_conversation':
          case 'send_workspace_message': return conversation
          case 'subscribe_workspace_conversation': return '01890e00-0000-7000-8000-000000000005'
          case 'ack_conversation_update':
          case 'cancel_conversation_subscription': return null
          case 'prepare_managed_task_run': {
            return { status: 'ready', generation: 1, projectId: project.projectId, workspaceId: workspace.workspaceId,
              conversationId, canStart: true, startUnavailableReason: null, authority, draftPolicy: 'memory_only', recoveryToken }
          }
          case 'start_managed_task_run': {
            const count = Number(localStorage.getItem('mock-managed-starts') ?? 0) + 1
            localStorage.setItem('mock-managed-starts', String(count))
            localStorage.setItem('mock-managed-token', String(args?.recoveryToken ?? ''))
            return uncertain
              ? { status: 'uncertain', taskRunId: null, streamVersion: null, recoveryToken }
              : { status: 'accepted', taskRunId, streamVersion: 2, recoveryToken }
          }
          case 'recover_managed_task_run': {
            localStorage.setItem('mock-managed-recovered-token', String(args?.recoveryToken ?? ''))
            return uncertain
              ? { status: 'uncertain', taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }
              : { status: 'accepted', taskRunId, streamVersion: 2, workspaceId: workspace.workspaceId, conversationId }
          }
          case 'get_task_run_timeline': return args?.taskRunId === taskRunId ? timeline : null
          case 'subscribe_task_run_timeline': return '01890e00-0000-7000-8000-000000000012'
          case 'cancel_task_run_subscription': return null
          case 'get_task_run_effects': return {
            taskRunId, streamVersion: 2, attemptId: null, cancellationRequested: false, localCommand: null,
            remote: { outcome: 'unknown', publication: 'unknown', accounting: 'unknown', cancellation: 'unknown', availability: 'unknown', capabilities: { statusCheck: false, streamResume: false, remoteCancel: false }, usageKnown: null },
            successor: 'blocked',
          }
          case 'get_project_trust_control': return {
            projectId: project.projectId, projectName: project.displayName, projectVersion: '1',
            workspaceId: workspace.workspaceId, workspaceName: workspace.displayName, workspaceVersion: '1',
            status: 'trusted', managedDenyMask: 0, provenance: 'user', epoch: '1', revision: '1', rootAdmissionVersion: null,
          }
          case 'set_theme': return null
          default: throw new Error(`unsupported managed composer mock command: ${command}`)
        }
      },
    }
  }, { project, workspace: managedWorkspace, conversation, conversationId, authority, recoveryToken, taskRunId, timeline, uncertain })
}
