<script setup lang="ts">
import { GcButton, GcProjectCard } from '@runne/product/shared/ui'
import { ArrowRight, Clock3, Folder, FolderOpen, FolderPlus } from 'lucide-vue-next'
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
    <header class="projects-page__header">
      <div>
        <h1 id="projects-title">
          {{ translate('projects.title') }}
        </h1>
        <p>{{ translate('projects.subtitle') }}</p>
        <p class="runtime-summary">
          {{ translate('projects.runtimeSummary', { status: runtimeStatus }) }}
        </p>
      </div>
      <GcButton
        :aria-label="translate('projects.openLocalProject')"
        @click="openProjectPicker"
      >
        <FolderPlus
          :size="16"
          aria-hidden="true"
        />
        {{ translate('projects.openProject') }}
      </GcButton>
    </header>

    <div class="projects-page__content">
      <section
        class="projects-recent"
        aria-labelledby="recent-projects-title"
      >
        <header class="projects-recent__header">
          <h2 id="recent-projects-title">
            Recent
          </h2>
          <p>{{ translate('projects.runtimeAuthority') }}</p>
        </header>

        <div class="projects-project-grid">
          <button
            class="project-card project-card--open"
            type="button"
            :aria-label="translate('projects.openLocalProject')"
            @click="openProjectPicker"
          >
            <span class="projects-card-icon">
              <FolderOpen
                :size="21"
                aria-hidden="true"
              />
            </span>
            <span class="project-copy">
              <strong>{{ translate('projects.openLocalProject') }}</strong>
              <small>{{ translate('projects.selectFolder') }}</small>
            </span>
            <ArrowRight
              class="projects-card-arrow"
              :size="17"
              aria-hidden="true"
            />
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
          >
            <template #leading>
              <Folder
                :size="20"
                aria-hidden="true"
              />
            </template>
            <template #trailing>
              <ArrowRight
                :size="17"
                aria-hidden="true"
              />
            </template>
          </GcProjectCard>
        </div>
      </section>
    </div>

    <footer
      v-if="loading"
      class="projects-page__state empty-state"
      aria-live="polite"
    >
      <h2>{{ translate('projects.loading') }}</h2>
    </footer>

    <footer
      v-else-if="error"
      class="projects-page__state empty-state"
      role="alert"
    >
      <h2>{{ translate('projects.unavailable') }}</h2>
      <p v-if="error !== null">
        {{ translate(error) }}
      </p>
    </footer>

    <footer
      v-else-if="projects.length === 0"
      class="projects-page__state empty-state"
    >
      <span class="empty-icon">
        <Clock3
          :size="24"
          aria-hidden="true"
        />
      </span>
      <h2>{{ translate('projects.noProjects') }}</h2>
      <p>{{ translate('projects.noProjectsMessage') }}</p>
    </footer>
  </section>
</template>
