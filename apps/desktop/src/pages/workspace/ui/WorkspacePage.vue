<script setup lang="ts">
import { GcAlert, GcButton, GcWorkspacePanel } from '@gocode/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { Folder, PanelRight } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import type { Project } from '@/entities/project'
import { getProject } from '@/entities/project'

type LoadProject = (id: number) => Promise<Project | null>

const props = withDefaults(defineProps<{
  loadProject?: LoadProject
}>(), {
  loadProject: async (id: number) => isTauri() ? getProject(id) : null,
})

const route = useRoute()
const router = useRouter()
const project = ref<Project | null>(null)
const loading = ref(true)
const error = ref(false)

onMounted(async () => {
  const id = Number(route.params.id)
  if (!Number.isSafeInteger(id) || id <= 0) {
    error.value = true
    loading.value = false
    return
  }
  try {
    project.value = await props.loadProject(id)
    error.value = project.value === null
  }
  catch {
    error.value = true
  }
  finally {
    loading.value = false
  }
})

async function returnToProjects() {
  await router.push('/')
}
</script>

<template>
  <section
    v-if="loading"
    class="empty-state"
    aria-live="polite"
  >
    <h1>Loading workspace</h1>
  </section>

  <section
    v-else-if="error || project === null"
    class="empty-state"
    role="alert"
  >
    <GcAlert
      level="error"
      title="Project unavailable"
    >
      The saved local project could not be restored.
    </GcAlert>
    <GcButton variant="secondary" @click="returnToProjects">
      Back to projects
    </GcButton>
  </section>

  <section
    v-else
    class="workspace-page"
    aria-labelledby="workspace-title"
  >
    <header class="workspace-header">
      <div>
        <span class="workspace-kicker">Local workspace</span>
        <h1 id="workspace-title">
          {{ project.name }}
        </h1>
        <p>{{ project.path }}</p>
      </div>
      <span class="workspace-status">Ready locally</span>
    </header>

    <div class="workspace-panels">
      <aside class="workspace-panel workspace-panel--tree">
        <div class="panel-heading">
          <Folder
            :size="15"
            aria-hidden="true"
          />
          <strong>Project</strong>
        </div>
        <p>{{ project.name }}</p>
      </aside>

      <div class="workspace-panel workspace-panel--main">
        <GcWorkspacePanel
          :tabs="[{ id: 'overview', label: 'Overview' }]"
          active-tab="overview"
          panel-state="empty"
        />
      </div>

      <aside class="workspace-panel workspace-panel--details">
        <div class="panel-heading">
          <PanelRight
            :size="15"
            aria-hidden="true"
          />
          <strong>Details</strong>
        </div>
        <dl>
          <dt>Location</dt>
          <dd>{{ project.path }}</dd>
          <dt>Runtime</dt>
          <dd>Offline</dd>
        </dl>
      </aside>
    </div>
  </section>
</template>
