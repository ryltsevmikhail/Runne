import type { RouteRecordRaw } from 'vue-router'

import { DiagnosticsPage } from '@/pages/diagnostics'
import { DevicesPage } from '@/pages/devices'
import { AppearancePage } from '@/pages/appearance'
import { ApprovalsPage } from '@/pages/approvals'
import { OpenProjectPage } from '@/pages/open-project'
import { ProjectDetailsPage } from '@/pages/project-details'
import { ProjectsPage } from '@/pages/projects'
import { ProvidersPage } from '@/pages/providers'
import { RuntimeSettingsPage } from '@/pages/runtime-settings'
import { SettingsPage } from '@/pages/settings'
import { ShortcutsPage } from '@/pages/shortcuts'
import { TaskRunPage } from '@/pages/task-run'
import { UpdatesPage } from '@/pages/updates'
import { WorkspacePage } from '@/pages/workspace'

export const routes: RouteRecordRaw[] = [
  {
    path: '/task-runs/:taskRunId',
    name: 'task-run',
    component: TaskRunPage,
  },
  {
    path: '/approvals',
    name: 'approvals',
    component: ApprovalsPage,
  },
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
    path: '/settings/runtimes',
    name: 'runtime-settings',
    component: RuntimeSettingsPage,
  },
  {
    path: '/settings/appearance',
    name: 'appearance-settings',
    component: AppearancePage,
  },
  {
    path: '/settings',
    name: 'settings',
    component: SettingsPage,
  },
  {
    path: '/settings/shortcuts',
    name: 'shortcuts-settings',
    component: ShortcutsPage,
  },
  {
    path: '/settings/providers',
    name: 'providers-settings',
    component: ProvidersPage,
  },
  {
    path: '/settings/devices',
    name: 'devices-settings',
    component: DevicesPage,
  },
  {
    path: '/settings/updates',
    name: 'updates-settings',
    component: UpdatesPage,
  },
  {
    path: '/settings/diagnostics',
    name: 'diagnostics',
    component: DiagnosticsPage,
  },
]
