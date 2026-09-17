import type { CanonicalProject, CanonicalProjectDetails, CanonicalWorkspaceMutationAck } from '@/entities/project'
import { getCanonicalProject, openCanonicalWorkspace } from '@/entities/project'

type LoadProject = (projectId: string) => Promise<CanonicalProjectDetails>
type OpenWorkspace = (workspaceId: string, expectedVersion: number) => Promise<CanonicalWorkspaceMutationAck>

export type ProjectOpenDestination = 'workspace' | 'project-details'

export interface ProjectOpenNavigation {
  openWorkspace(workspaceId: string): Promise<void>
  openProjectDetails(projectId: string): Promise<void>
}

export class ProjectWorkspaceOpenError extends Error {
  constructor() {
    super('Project workspace could not be opened')
  }
}

export async function openProjectWorkspace(
  project: CanonicalProject,
  isRuntimeLive: () => boolean,
  navigation: ProjectOpenNavigation,
  loadProject: LoadProject = getCanonicalProject,
  openWorkspace: OpenWorkspace = openCanonicalWorkspace,
): Promise<ProjectOpenDestination> {
  if (!isRuntimeLive()) throw new ProjectWorkspaceOpenError()
  if (project.archived) return openProjectDetails(project.projectId, navigation)

  const details = await loadProject(project.projectId)
  if (!isRuntimeLive()) throw new ProjectWorkspaceOpenError()
  if (details.project.archived || details.workspaces.length !== 1) {
    return openProjectDetails(project.projectId, navigation)
  }

  const [workspace] = details.workspaces
  if (workspace === undefined) return openProjectDetails(project.projectId, navigation)
  if (!workspace.open) {
    await openWorkspace(workspace.workspaceId, workspace.version)
    if (!isRuntimeLive()) throw new ProjectWorkspaceOpenError()
  }
  await navigation.openWorkspace(workspace.workspaceId)
  return 'workspace'
}

async function openProjectDetails(
  projectId: string,
  navigation: ProjectOpenNavigation,
): Promise<ProjectOpenDestination> {
  await navigation.openProjectDetails(projectId)
  return 'project-details'
}
