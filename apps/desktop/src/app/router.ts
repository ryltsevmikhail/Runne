import type { RouteRecordRaw } from 'vue-router'

import { ProjectsPage } from '@/pages/projects'
import { RuntimeSettingsPage } from '@/pages/runtime-settings'

export const routes: RouteRecordRaw[] = [
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
