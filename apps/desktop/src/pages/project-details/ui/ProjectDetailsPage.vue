<script setup lang="ts">
import { GcAlert, GcButton } from '@gocode/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { ArrowRight, FolderOpen } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import type { Project } from '@/entities/project'
import { getProject } from '@/entities/project'

type LoadProject = (id: string) => Promise<readonly Project[]>

const props = withDefaults(defineProps<{
  loadProject?: LoadProject
}>(), {
  loadProject: async (id: string) => isTauri() ? getProject(id) : [],
})

const route = useRoute()
const router = useRouter()
const projects = ref<readonly Project[]>([])
const loading = ref(true)
const error = ref(false)

onMounted(async () => {
  const id = typeof route.params.projectId === 'string' ? route.params.projectId : ''
  if (id === '') {
    error.value = true
    loading.value = false
    return
  }
  try {
    projects.value = await props.loadProject(id)
    error.value = projects.value.length === 0
  }
  catch {
    error.value = true
  }
  finally {
    loading.value = false
  }
})

async function openWorkspace(workspaceId: string) {
  await router.push({
    name: 'workspace',
    params: { workspaceId },
  })
}

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
    <h1>Loading project</h1>
  </section>

  <section
    v-else-if="error || projects.length === 0"
    class="empty-state"
    role="alert"
  >
    <GcAlert
      level="error"
      title="Project unavailable"
    >
      The saved local project could not be restored.
    </GcAlert>
    <GcButton
      variant="secondary"
      @click="returnToProjects"
    >
      Back to projects
    </GcButton>
  </section>

  <section
    v-else
    aria-labelledby="project-title"
  >
    <header class="page-header">
      <div>
        <span class="workspace-kicker">Local project</span>
        <h1 id="project-title">
          {{ projects[0]?.displayName }}
        </h1>
        <p>Local root</p>
      </div>
    </header>

    <div class="content-section">
      <div class="section-heading">
        <h2>Workspaces</h2>
        <span>Local</span>
      </div>
      <button
        v-for="project in projects"
        :key="project.workspaceId"
        class="project-card project-card--workspace"
        type="button"
        :aria-label="`Open workspace ${project.displayName}`"
        @click="openWorkspace(project.workspaceId)"
      >
        <span class="project-icon">
          <FolderOpen
            :size="21"
            aria-hidden="true"
          />
        </span>
        <span class="project-copy">
          <strong>{{ project.displayName }}</strong>
          <small>Local root</small>
        </span>
        <ArrowRight
          class="project-arrow"
          :size="16"
          aria-hidden="true"
        />
      </button>
    </div>
  </section>
</template>
