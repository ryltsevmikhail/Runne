<script setup lang="ts">
import { GcButton } from '@runne/product/shared/ui'
import { FolderOpen } from 'lucide-vue-next'
import { onBeforeUnmount, ref, watch } from 'vue'

import { LocalProjectOpenError, selectAndCreateLocalProject, type LocalProjectOpenResult } from '@/features/open-local-project'
import { translate } from '@/shared/i18n'
import { useRoute, useRouter } from 'vue-router'

type OpenProject = () => Promise<LocalProjectOpenResult | null>

const props = withDefaults(defineProps<{
  openProject?: OpenProject
}>(), {
  openProject: selectAndCreateLocalProject,
})

const router = useRouter()
const route = useRoute()
const opening = ref(false)
const error = ref<string | null>(null)
let requestGeneration = 0
let alive = true
onBeforeUnmount(() => {
  alive = false
  requestGeneration += 1
})
watch(() => route.fullPath, () => { requestGeneration += 1 })

async function chooseFolder() {
  const generation = ++requestGeneration
  const routeAtStart = route.fullPath
  opening.value = true
  error.value = null
  try {
    const opened = await props.openProject()
    if (alive && generation === requestGeneration && route.fullPath === routeAtStart && opened !== null) {
      await router.push({
        name: 'workspace',
        params: { workspaceId: opened.workspaceId },
      })
    }
  }
  catch (failure) {
    if (alive && generation === requestGeneration && route.fullPath === routeAtStart) {
      error.value = translate(failure instanceof LocalProjectOpenError
        ? `openProject.${failure.stage}Failed` : 'openProject.openFailed')
    }
  }
  finally {
    if (alive && generation === requestGeneration) opening.value = false
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
        <h1 id="open-project-title">
          {{ translate('openProject.title') }}
        </h1>
        <p>{{ translate('openProject.description') }}</p>
      </header>

      <GcButton
        class="open-project-page__choose-button"
        size="sm"
        :aria-label="translate('openProject.chooseFolder')"
        :disabled="opening"
        @click="chooseFolder"
      >
        <FolderOpen
          :size="16"
          aria-hidden="true"
        />
        {{ opening ? translate('openProject.opening') : translate('openProject.chooseFolderAction') }}
      </GcButton>

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
