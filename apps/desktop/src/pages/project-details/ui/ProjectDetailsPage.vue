<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { ArrowRight, FolderOpen } from 'lucide-vue-next'
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

async function openWorkspace() {
  if (project.value === null) {
    return
  }
  await router.push({
    name: 'workspace',
    params: { id: project.value.id },
  })
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
    v-else-if="error || project === null"
    class="empty-state"
    role="alert"
  >
    <h1>Project unavailable</h1>
    <p>The saved local project could not be restored.</p>
    <RouterLink
      class="primary-button"
      to="/"
    >
      Back to projects
    </RouterLink>
  </section>

  <section
    v-else
    aria-labelledby="project-title"
  >
    <header class="page-header">
      <div>
        <span class="workspace-kicker">Local project</span>
        <h1 id="project-title">
          {{ project.name }}
        </h1>
        <p>{{ project.path }}</p>
      </div>
    </header>

    <div class="content-section">
      <div class="section-heading">
        <h2>Workspaces</h2>
        <span>Local</span>
      </div>
      <button
        class="project-card project-card--workspace"
        type="button"
        :aria-label="`Open workspace ${project.name}`"
        @click="openWorkspace"
      >
        <span class="project-icon">
          <FolderOpen
            :size="21"
            aria-hidden="true"
          />
        </span>
        <span class="project-copy">
          <strong>{{ project.name }}</strong>
          <small>{{ project.path }}</small>
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
