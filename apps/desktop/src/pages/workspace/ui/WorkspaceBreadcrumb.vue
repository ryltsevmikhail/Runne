<script setup lang="ts">
import { ChevronRight } from 'lucide-vue-next'

import { translate } from '@/shared/i18n'

defineProps<{
  projectId: string
  projectName: string
}>()
</script>

<template>
  <nav
    class="workspace-breadcrumb"
    :aria-label="translate('workspace.breadcrumbLabel')"
  >
    <RouterLink to="/">
      {{ translate('workspace.breadcrumbProjects') }}
    </RouterLink>
    <ChevronRight
      class="workspace-breadcrumb__separator"
      :size="13"
      aria-hidden="true"
    />
    <RouterLink :to="{ name: 'project-details', params: { projectId } }">
      {{ projectName }}
    </RouterLink>
    <ChevronRight
      class="workspace-breadcrumb__separator"
      :size="13"
      aria-hidden="true"
    />
    <span aria-current="page">{{ translate('workspace.breadcrumbWorkspace') }}</span>
  </nav>
</template>
