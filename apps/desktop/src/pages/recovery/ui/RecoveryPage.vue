<script setup lang="ts">
import { translate } from '@/shared/i18n'
import { TargetCapabilityBoundary } from '@/shared/ui/target-capability'
</script>

<template>
  <section
    class="recovery-page"
    aria-labelledby="recovery-page-title"
  >
    <header class="recovery-page__header">
      <div>
        <h1 id="recovery-page-title">
          {{ translate('recovery.title') }}
        </h1>
        <p>{{ translate('recovery.subtitle') }}</p>
      </div>
    </header>

    <main class="recovery-page__content">
      <div class="recovery-page__state">
        <TargetCapabilityBoundary
          data-capability="recovery-orchestration"
          :title="translate('targetCapability.unavailable')"
          :description="translate('targetCapability.unavailableDescription', { capability: 'recovery-orchestration' })"
          capability="recovery-orchestration"
        />
        <aside class="recovery-page__ownership-notice">
          {{ translate('recovery.ownershipNotice') }}
        </aside>
        <p class="recovery-page__explanation">
          {{ translate('recovery.explanation') }}
        </p>
        <RouterLink
          class="recovery-page__back-link"
          to="/"
        >
          {{ translate('recovery.backToProjects') }}
        </RouterLink>
      </div>
    </main>
  </section>
</template>
