<script setup lang="ts">
import { Save } from 'lucide-vue-next'
import { computed, nextTick, ref } from 'vue'

import { translate, type LocaleKey } from '@/shared/i18n'
import { TargetCapabilityBoundary } from '@/shared/ui/target-capability'

const categoryDefinitions = [
  { id: 'agents', labelKey: 'runtimeConfiguration.category.agents' },
  { id: 'models-providers', labelKey: 'runtimeConfiguration.category.modelsProviders' },
  { id: 'runtime-profiles', labelKey: 'runtimeConfiguration.category.runtimeProfiles' },
  { id: 'capabilities', labelKey: 'runtimeConfiguration.category.capabilities' },
  { id: 'mcp-tools', labelKey: 'runtimeConfiguration.category.mcpTools' },
  { id: 'devices', labelKey: 'runtimeConfiguration.category.devices' },
] as const satisfies ReadonlyArray<{ id: string, labelKey: LocaleKey }>
type CategoryId = typeof categoryDefinitions[number]['id']

const focusedCategory = ref<CategoryId>('agents')
const categories = computed(() => categoryDefinitions.map(category => ({
  ...category,
  label: translate(category.labelKey),
})))
const focusedDetail = computed(() => categories.value.find(category => category.id === focusedCategory.value)!)

function focusCategory(category: CategoryId) {
  focusedCategory.value = category
}

async function focusCategoryFromKeyboard(event: KeyboardEvent, category: CategoryId) {
  const categoryIndex = categoryDefinitions.findIndex(item => item.id === category)
  const offset = event.key === 'ArrowDown' || event.key === 'ArrowRight'
    ? 1
    : event.key === 'ArrowUp' || event.key === 'ArrowLeft' ? -1 : null
  const targetIndex = event.key === 'Home'
    ? 0
    : event.key === 'End'
      ? categoryDefinitions.length - 1
      : offset === null ? null : (categoryIndex + offset + categoryDefinitions.length) % categoryDefinitions.length

  if (targetIndex === null) return
  event.preventDefault()
  const targetCategory = categoryDefinitions[targetIndex]!
  focusCategory(targetCategory.id)
  await nextTick()
  document.getElementById(`runtime-configuration-tab-${targetCategory.id}`)?.focus()
}
</script>

<template>
  <section
    class="runtime-configuration-page"
    aria-labelledby="runtime-configuration-title"
  >
    <header class="runtime-configuration-page__header">
      <div>
        <h1 id="runtime-configuration-title">
          {{ translate('runtimeConfiguration.title') }}
        </h1>
        <p>{{ translate('runtimeConfiguration.subtitle') }}</p>
      </div>
      <span class="runtime-configuration-page__badge">
        {{ translate('runtimeConfiguration.ownershipBadge') }}
      </span>
      <button
        type="button"
        name="save-runtime-configuration"
        disabled
        aria-describedby="runtime-configuration-save-unavailable"
      >
        <Save
          :size="16"
          aria-hidden="true"
        />
        {{ translate('runtimeConfiguration.save') }}
      </button>
    </header>

    <main class="runtime-configuration-page__content">
      <aside class="runtime-configuration-page__ownership-notice">
        {{ translate('runtimeConfiguration.ownershipNotice') }}
      </aside>
      <TargetCapabilityBoundary
        data-capability="runtime-configuration"
        :title="translate('targetCapability.unavailable')"
        :description="translate('targetCapability.unavailableDescription', { capability: 'runtime-configuration' })"
        capability="runtime-configuration"
      />
      <div class="runtime-configuration-page__columns">
        <nav
          class="runtime-configuration-page__categories"
          role="tablist"
          aria-orientation="vertical"
          :aria-label="translate('runtimeConfiguration.categories')"
        >
          <button
            v-for="category in categories"
            :id="`runtime-configuration-tab-${category.id}`"
            :key="category.id"
            type="button"
            role="tab"
            :data-config-section="category.id"
            :class="{ 'runtime-configuration-page__category--focused': focusedCategory === category.id }"
            aria-controls="runtime-configuration-panel"
            :aria-selected="focusedCategory === category.id"
            :tabindex="focusedCategory === category.id ? 0 : -1"
            @click="focusCategory(category.id)"
            @keydown="focusCategoryFromKeyboard($event, category.id)"
          >
            {{ category.label }}
          </button>
        </nav>
        <section
          id="runtime-configuration-panel"
          class="runtime-configuration-page__detail"
          role="tabpanel"
          aria-live="polite"
          :aria-label="translate('runtimeConfiguration.details')"
          :aria-labelledby="`runtime-configuration-tab-${focusedDetail.id}`"
          data-config-detail
        >
          <h2>{{ focusedDetail.label }}</h2>
          <p>{{ translate('runtimeConfiguration.capabilityDescription') }}</p>
        </section>
      </div>
      <p
        id="runtime-configuration-save-unavailable"
        class="runtime-configuration-page__save-notice"
        role="status"
      >
        {{ translate('runtimeConfiguration.saveUnavailable') }}
      </p>
    </main>
  </section>
</template>
