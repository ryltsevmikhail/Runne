<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import type { SettingsPageAdapter, SettingsPageSnapshot } from '../model/page-state'
import { loadOwnedLocale, translate, type LocaleKey } from '@/shared/i18n'

const props = defineProps<{
  readonly title: string
  readonly titleKey?: LocaleKey
  readonly adapter: SettingsPageAdapter
}>()

const snapshot = ref<SettingsPageSnapshot | null>(null)
const loading = ref(true)
const displayTitle = computed(() => props.titleKey === undefined ? props.title : translate(props.titleKey))

async function request(requestSnapshot: () => Promise<SettingsPageSnapshot>) {
  loading.value = true
  try {
    snapshot.value = await requestSnapshot()
  }
  catch {
    snapshot.value = {
      kind: 'unavailable',
      message: `${displayTitle.value} could not be read from its desktop owner.`,
    }
  }
  finally {
    loading.value = false
  }
}

async function recover() {
  await request(props.adapter.recover ?? props.adapter.load)
}

onMounted(async () => {
  try {
    await loadOwnedLocale()
  }
  catch {
    // The owner remains fail-closed; English is the safe renderer fallback.
  }
  await request(props.adapter.load)
})
</script>

<template>
  <section
    v-if="loading"
    aria-live="polite"
  >
    <h1>{{ translate('settings.loading', { page: displayTitle.toLowerCase() }) }}</h1>
  </section>

  <section
    v-else-if="snapshot?.kind === 'unavailable'"
    role="alert"
  >
    <h1>{{ displayTitle }}</h1>
    <p>{{ snapshot.message }}</p>
  </section>

  <section
    v-else-if="snapshot?.kind === 'recovery'"
    role="status"
  >
    <h1>{{ displayTitle }}</h1>
    <p>{{ snapshot.message }}</p>
    <button
      type="button"
      @click="recover"
    >
      {{ translate('settings.retry') }}
    </button>
  </section>

  <section v-else>
    <h1>{{ displayTitle }}</h1>
    <dl>
      <div
        v-for="item in snapshot?.items"
        :key="item.label"
      >
        <dt>{{ item.label }}</dt>
        <dd>{{ item.detail }}</dd>
      </div>
    </dl>
  </section>
</template>
