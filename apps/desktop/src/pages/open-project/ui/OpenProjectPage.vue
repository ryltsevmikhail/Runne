<script setup lang="ts">
import { FolderOpen } from 'lucide-vue-next'
import { ref } from 'vue'
import { useRouter } from 'vue-router'

import type { Project } from '@/entities/project'
import { selectAndOpenLocalProject } from '@/features/open-local-project'

type OpenProject = () => Promise<Project | null>

const props = withDefaults(defineProps<{
  openProject?: OpenProject
}>(), {
  openProject: selectAndOpenLocalProject,
})

const router = useRouter()
const opening = ref(false)
const error = ref<string | null>(null)

async function chooseFolder() {
  opening.value = true
  error.value = null
  try {
    const project = await props.openProject()
    if (project !== null) {
      await router.push({
        name: 'project-details',
        params: { id: project.id },
      })
    }
  }
  catch {
    error.value = 'The selected folder could not be opened.'
  }
  finally {
    opening.value = false
  }
}
</script>

<template>
  <section
    class="projects-page"
    aria-labelledby="open-project-title"
  >
    <header class="page-header">
      <div>
        <p class="eyebrow">
          Local project
        </p>
        <h1 id="open-project-title">
          Open a project
        </h1>
        <p>Select a folder on this device. GOCODE stores only the local project record.</p>
      </div>
    </header>

    <div class="content-section">
      <button
        class="project-card project-card--open"
        type="button"
        aria-label="Choose project folder"
        :disabled="opening"
        @click="chooseFolder"
      >
        <span class="project-icon">
          <FolderOpen
            :size="21"
            aria-hidden="true"
          />
        </span>
        <span class="project-copy">
          <strong>{{ opening ? 'Opening…' : 'Choose folder' }}</strong>
          <small>The folder remains on this device</small>
        </span>
        <span class="project-arrow">→</span>
      </button>

      <p
        v-if="error"
        role="alert"
        class="form-error"
      >
        {{ error }}
      </p>
    </div>
  </section>
</template>
