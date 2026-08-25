<script setup lang="ts">
import { FolderOpen } from 'lucide-vue-next'
import { ref } from 'vue'

import { selectAndCreateLocalProject, type LocalProjectOpenResult } from '@/features/open-local-project'
import { translate } from '@/shared/i18n'
import { useRouter } from 'vue-router'

type OpenProject = () => Promise<LocalProjectOpenResult | null>

const props = withDefaults(defineProps<{
  openProject?: OpenProject
}>(), {
  openProject: selectAndCreateLocalProject,
})

const router = useRouter()
const opening = ref(false)
const error = ref<string | null>(null)

async function chooseFolder() {
  opening.value = true
  error.value = null
  try {
    const opened = await props.openProject()
    if (opened !== null) {
      await router.push({
        name: 'workspace',
        params: { workspaceId: opened.workspaceId },
      })
    }
  }
  catch {
    error.value = translate('openProject.openFailed')
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
          {{ translate('openProject.localProject') }}
        </p>
        <h1 id="open-project-title">
          {{ translate('openProject.title') }}
        </h1>
        <p>{{ translate('openProject.description') }}</p>
      </div>
    </header>

    <div class="content-section">
      <button
        class="project-card project-card--open"
        type="button"
        :aria-label="translate('openProject.chooseFolder')"
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
          <strong>{{ opening ? translate('openProject.opening') : translate('openProject.chooseFolderAction') }}</strong>
          <small>{{ translate('openProject.folderOnDevice') }}</small>
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
