<script setup lang="ts">
import { ArrowRight, FolderOpen, Info } from 'lucide-vue-next'
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
    class="projects-page open-project-page"
    aria-labelledby="open-project-title"
  >
    <div class="open-project-page__content">
      <header class="open-project-page__header">
        <p class="eyebrow">
          {{ translate('openProject.localProject') }}
        </p>
        <h1 id="open-project-title">
          {{ translate('openProject.title') }}
        </h1>
        <p>{{ translate('openProject.description') }}</p>
      </header>

      <button
        class="project-card project-card--open open-project-page__choose-card"
        type="button"
        :aria-label="translate('openProject.chooseFolder')"
        :disabled="opening"
        @click="chooseFolder"
      >
        <span class="projects-card-icon">
          <FolderOpen
            :size="21"
            aria-hidden="true"
          />
        </span>
        <span class="project-copy">
          <strong>{{ opening ? translate('openProject.opening') : translate('openProject.chooseFolderAction') }}</strong>
          <small>{{ translate('openProject.folderOnDevice') }}</small>
        </span>
        <ArrowRight
          class="projects-card-arrow"
          :size="19"
          aria-hidden="true"
        />
      </button>

      <aside class="open-project-page__privacy">
        <Info
          :size="16"
          aria-hidden="true"
        />
        <span>{{ translate('openProject.folderOnDevice') }}</span>
      </aside>

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
