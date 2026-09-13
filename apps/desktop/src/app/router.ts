import type { RouteRecordRaw } from 'vue-router'

import { DiagnosticsPage } from '@/pages/diagnostics'
import { DevicesPage } from '@/pages/devices'
import { AppearancePage } from '@/pages/appearance'
import { ApprovalsPage } from '@/pages/approvals'
import { OpenProjectPage } from '@/pages/open-project'
import { ProjectsPage } from '@/pages/projects'
import { ProvidersPage } from '@/pages/providers'
import { RecoveryPage } from '@/pages/recovery'
import { RuntimeConfigurationPage, RuntimeSettingsPage } from '@/pages/runtime-settings'
import { SettingsPage } from '@/pages/settings'
import { ShortcutsPage } from '@/pages/shortcuts'
import { TaskRunPage } from '@/pages/task-run'
import { TaskRunInventoryPage } from '@/pages/task-run-inventory'
import { UpdatesPage } from '@/pages/updates'
import { WorkspacePage } from '@/pages/workspace'

export const routes: RouteRecordRaw[] = [
  {
    path: '/recovery',
    name: 'recovery',
    component: RecoveryPage,
  },
  {
    path: '/task-runs',
    name: 'task-run-inventory',
    component: TaskRunInventoryPage,
  },
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
    redirect: to => ({ path: '/', query: { project: String(to.params.projectId) } }),
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
    path: '/settings/runtime-configuration',
    name: 'runtime-configuration',
    component: RuntimeConfigurationPage,
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
