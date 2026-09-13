<script setup lang="ts">
import { GcButton } from '@runne/product/shared/ui'
import { FolderOpen } from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { translate } from '@/shared/i18n'

const router = useRouter()
</script>

<template>
  <section
    class="projects-page projects-start"
    aria-labelledby="projects-title"
  >
    <div class="projects-start__content">
      <h1 id="projects-title">
        {{ translate('projects.title') }}
      </h1>
      <p>{{ translate('projects.sidebarHint') }}</p>
      <GcButton
        size="sm"
        variant="secondary"
        @click="router.push({ name: 'open-project' })"
      >
        <FolderOpen
          :size="16"
          aria-hidden="true"
        />
        {{ translate('projects.openLocalProject') }}
      </GcButton>
    </div>
  </section>
</template>
