<script setup lang="ts">
import { GcButton, GcProjectCard } from '@gocode/product/shared/ui'
import { Clock3, FolderOpen, Plus } from 'lucide-vue-next'
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import type { Project } from '@/entities/project'
import { listProjects } from '@/entities/project'

type LoadProjects = () => Promise<readonly Project[]>

const props = withDefaults(defineProps<{
  loadProjects?: LoadProjects
}>(), {
  loadProjects: listProjects,
})

const router = useRouter()
const projects = ref<readonly Project[]>([])
const loading = ref(true)
const error = ref<string | null>(null)

onMounted(async () => {
  try {
    projects.value = await props.loadProjects()
  }
  catch {
    error.value = 'Projects could not be loaded.'
  }
  finally {
    loading.value = false
  }
})

async function openProjectPicker() {
  await router.push({ name: 'open-project' })
}

async function openProjectDetails(project: Project) {
  await router.push({
    name: 'project-details',
    params: { projectId: project.projectId },
  })
}
</script>

<template>
  <section
    class="projects-page"
    aria-labelledby="projects-title"
  >
    <header class="page-header">
      <div>
        <h1 id="projects-title">
          Projects
        </h1>
        <p>Choose a workspace and continue where you left off.</p>
      </div>
      <GcButton
        aria-label="Open local project"
        @click="openProjectPicker"
      >
        <Plus
          :size="16"
          aria-hidden="true"
        />
        Open project
      </GcButton>
    </header>

    <div class="content-section">
      <div class="section-heading">
        <h2>Recent</h2>
        <span>Local workspaces</span>
      </div>

      <div class="project-grid">
        <button
          class="project-card project-card--open"
          type="button"
          aria-label="Open local project"
          @click="openProjectPicker"
        >
          <span class="project-icon">
            <FolderOpen
              :size="21"
              aria-hidden="true"
            />
          </span>
          <span class="project-copy">
            <strong>Open local project</strong>
            <small>Select a folder on this device</small>
          </span>
          <span class="project-arrow">→</span>
        </button>
        <GcProjectCard
          v-for="project in projects"
          :key="project.workspaceId"
          :project="{
            name: project.displayName,
            path: 'Local root',
            slug: project.workspaceId,
            modifiedAt: new Date(project.lastOpenedAt).toLocaleDateString(),
          }"
          :aria-label="`Open project ${project.displayName}`"
          @click="openProjectDetails(project)"
        />
      </div>
    </div>

    <div
      v-if="loading"
      class="empty-state"
      aria-live="polite"
    >
      <h2>Loading projects</h2>
    </div>

    <div
      v-else-if="error"
      class="empty-state"
      role="alert"
    >
      <h2>Projects unavailable</h2>
      <p>{{ error }}</p>
    </div>

    <div
      v-else-if="projects.length === 0"
      class="empty-state"
    >
      <span class="empty-icon">
        <Clock3
          :size="24"
          aria-hidden="true"
        />
      </span>
      <h2>No recent projects</h2>
      <p>Your local projects will appear here after you open them.</p>
    </div>
  </section>
</template>
