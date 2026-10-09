<script setup lang="ts">
import { PanelRight } from 'lucide-vue-next'

import type { CanonicalWorkspace } from '@/entities/project'
import { translate } from '@/shared/i18n'
import WorkspacePermissionMode from './WorkspacePermissionMode.vue'

defineProps<{
  project: CanonicalWorkspace
  runtimeStatus: string
}>()
</script>

<template>
  <div class="panel-heading">
    <PanelRight
      :size="15"
      aria-hidden="true"
    />
    <strong>{{ translate('workspace.details') }}</strong>
  </div>
  <dl>
    <dt>{{ translate('workspace.runtime') }}</dt>
    <dd>{{ runtimeStatus }}</dd>
    <dt>{{ translate('workspace.workspace') }}</dt>
    <dd>
      {{ translate('workspace.versionState', {
        version: project.version,
        state: project.open ? translate('projectDetails.open') : translate('projectDetails.closed'),
      }) }}
    </dd>
  </dl>
  <WorkspacePermissionMode
    :workspace-id="project.workspaceId"
    :runtime-ready="runtimeStatus === 'live'"
  />
</template>
