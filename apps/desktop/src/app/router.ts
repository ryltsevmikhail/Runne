import type { RouteRecordRaw } from 'vue-router'

import { DiagnosticsPage } from '@/pages/diagnostics'
import { OpenProjectPage } from '@/pages/open-project'
import { ProjectDetailsPage } from '@/pages/project-details'
import { ProjectsPage } from '@/pages/projects'
import { RuntimeSettingsPage } from '@/pages/runtime-settings'
import { TaskRunsPage } from '@/pages/task-runs'
import { WorkspacePage } from '@/pages/workspace'

export const routes: RouteRecordRaw[] = [
  {
    path: '/projects/open',
    name: 'open-project',
    component: OpenProjectPage,
  },
  {
    path: '/projects/:projectId',
    name: 'project-details',
    component: ProjectDetailsPage,
  },
  {
    path: '/workspaces/:workspaceId',
    name: 'workspace',
    component: WorkspacePage,
  },
  {
    path: '/',
    name: 'projects',
    component: ProjectsPage,
  },
  {
    path: '/task-runs',
    name: 'task-runs',
    component: TaskRunsPage,
  },
  {
    path: '/settings/runtimes',
    name: 'runtime-settings',
    component: RuntimeSettingsPage,
  },
  {
    path: '/diagnostics',
    alias: '/settings/diagnostics',
    name: 'diagnostics',
    component: DiagnosticsPage,
  },
]
