import type { RouteRecordRaw } from 'vue-router'

import { ProjectsPage } from '@/pages/projects'
import { RuntimeSettingsPage } from '@/pages/runtime-settings'
import { WorkspacePage } from '@/pages/workspace'

export const routes: RouteRecordRaw[] = [
  {
    path: '/workspaces/:id',
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
]
