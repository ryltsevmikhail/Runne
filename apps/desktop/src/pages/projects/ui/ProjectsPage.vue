<script setup lang="ts">
import { GcButton, GcProjectCard } from '@runne/product/shared/ui'
import { Clock3, FolderOpen, Plus } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'

import type { CanonicalProject } from '@/entities/project'
import { listCanonicalProjects } from '@/entities/project'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate, type LocaleKey } from '@/shared/i18n'

type LoadProjects = () => Promise<readonly CanonicalProject[]>

const props = withDefaults(defineProps<{
  loadProjects?: LoadProjects
}>(), {
  loadProjects: listCanonicalProjects,
})

const router = useRouter()
const projects = ref<readonly CanonicalProject[]>([])
const loading = ref(true)
const error = ref<LocaleKey | null>(null)
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')

async function refreshProjects() {
  error.value = null
  loading.value = true
  try {
    projects.value = await props.loadProjects()
  }
  catch {
    error.value = 'projects.loadFailed'
  }
  finally {
    loading.value = false
  }
}

watch(runtimeStatus, status => {
  if (runtimeSession === undefined) {
    error.value = 'projects.runtimeUnavailable'
    loading.value = false
    return
  }
  if (status === 'live') {
    void refreshProjects()
  }
  else {
    error.value = 'projects.runtimeUnavailable'
    loading.value = false
  }
}, { immediate: true })

async function openProjectPicker() {
  await router.push({ name: 'open-project' })
}

async function openProjectDetails(project: CanonicalProject) {
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
          {{ translate('projects.title') }}
        </h1>
        <p>{{ translate('projects.subtitle') }}</p>
        <p class="runtime-summary">{{ translate('projects.runtimeSummary', { status: runtimeStatus }) }}</p>
      </div>
      <GcButton
        :aria-label="translate('projects.openLocalProject')"
        @click="openProjectPicker"
      >
        <Plus
          :size="16"
          aria-hidden="true"
        />
        {{ translate('projects.openProject') }}
      </GcButton>
    </header>

    <div class="content-section">
      <div class="section-heading">
        <h2>{{ translate('projects.runtimeCatalog') }}</h2>
        <span>{{ translate('projects.runtimeAuthority') }}</span>
      </div>

      <div class="project-grid">
        <button
          class="project-card project-card--open"
          type="button"
          :aria-label="translate('projects.openLocalProject')"
          @click="openProjectPicker"
        >
          <span class="project-icon">
            <FolderOpen
              :size="21"
              aria-hidden="true"
            />
          </span>
          <span class="project-copy">
            <strong>{{ translate('projects.openLocalProject') }}</strong>
            <small>{{ translate('projects.selectFolder') }}</small>
          </span>
          <span class="project-arrow">→</span>
        </button>
        <GcProjectCard
          v-for="project in projects"
          :key="project.projectId"
          :project="{
            name: project.displayName,
            path: project.archived ? translate('projects.archived') : translate('projects.runtimeProject'),
            slug: project.projectId,
            modifiedAt: translate('projects.version', { version: project.version }),
          }"
          :aria-label="`${translate('projects.openProject')} ${project.displayName}`"
          @click="openProjectDetails(project)"
        />
      </div>
    </div>

    <div
      v-if="loading"
      class="empty-state"
      aria-live="polite"
    >
      <h2>{{ translate('projects.loading') }}</h2>
    </div>

    <div
      v-else-if="error"
      class="empty-state"
      role="alert"
    >
      <h2>{{ translate('projects.unavailable') }}</h2>
      <p v-if="error !== null">{{ translate(error) }}</p>
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
      <h2>{{ translate('projects.noProjects') }}</h2>
      <p>{{ translate('projects.noProjectsMessage') }}</p>
    </div>
  </section>
</template>
