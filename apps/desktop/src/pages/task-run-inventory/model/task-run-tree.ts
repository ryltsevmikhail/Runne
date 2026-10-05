import type { CanonicalProject, CanonicalProjectDetails } from '@/entities/project'
import type { ManagedTaskRunSummary } from '@/entities/task-run'

export interface TaskRunWorkspaceGroup {
  readonly workspaceId: string
  readonly workspaceName: string
  readonly taskRuns: readonly ManagedTaskRunSummary[]
}
export interface TaskRunProjectGroup {
  readonly projectId: string
  readonly projectName: string
  readonly workspaces: readonly TaskRunWorkspaceGroup[]
}
export interface TaskRunTree {
  readonly projects: readonly TaskRunProjectGroup[]
  readonly unmapped: readonly ManagedTaskRunSummary[]
}

export function buildTaskRunTree(projects: readonly CanonicalProject[], details: readonly CanonicalProjectDetails[], taskRuns: readonly ManagedTaskRunSummary[]): TaskRunTree {
  const byWorkspace = new Map<string, { projectId: string, projectName: string, workspaceName: string }>()
  for (const detail of details) {
    for (const workspace of detail.workspaces) byWorkspace.set(workspace.workspaceId, {
      projectId: detail.project.projectId, projectName: detail.project.displayName, workspaceName: workspace.displayName,
    })
  }
  const grouped = new Map<string, { projectName: string, workspaces: Map<string, { workspaceName: string, taskRuns: ManagedTaskRunSummary[] }> }>()
  const unmapped: ManagedTaskRunSummary[] = []
  for (const run of taskRuns) {
    const workspace = run.workspaceId === null ? undefined : byWorkspace.get(run.workspaceId)
    if (workspace === undefined) { unmapped.push(run); continue }
    const project = grouped.get(workspace.projectId) ?? { projectName: workspace.projectName, workspaces: new Map() }
    const workspaceGroup = project.workspaces.get(run.workspaceId!) ?? { workspaceName: workspace.workspaceName, taskRuns: [] }
    workspaceGroup.taskRuns.push(run)
    project.workspaces.set(run.workspaceId!, workspaceGroup)
    grouped.set(workspace.projectId, project)
  }
  const projectById = new Map(projects.map(project => [project.projectId, project]))
  return {
    projects: [...grouped].map(([projectId, project]) => ({
      projectId, projectName: projectById.get(projectId)?.displayName ?? project.projectName,
      workspaces: [...project.workspaces].map(([workspaceId, workspace]) => ({ workspaceId, ...workspace })),
    })).sort((a, b) => a.projectName.localeCompare(b.projectName)),
    unmapped,
  }
}
