<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { AppTheme } from '@/shared/model/theme'
import { appTheme } from '@/shared/model/theme'
import type { BootstrapState } from '@/shared/api/platform/bootstrap'
import { loadBootstrap, saveTheme } from '@/shared/api/platform/bootstrap'
import { loadLocale as loadOwnedLocaleSetting, saveLocale as saveOwnedLocaleSetting, type Locale } from '@/shared/api/platform/locale'
import { currentLocale, translate } from '@/shared/i18n'

type AppearanceState = Pick<BootstrapState, 'theme'>
type LoadAppearance = () => Promise<AppearanceState>
type SaveAppearance = (theme: AppTheme) => Promise<void>
type LoadLocale = () => Promise<{ locale: Locale }>
type SaveLocale = (locale: Locale) => Promise<void>

const props = withDefaults(defineProps<{
  loadAppearance?: LoadAppearance
  saveAppearance?: SaveAppearance
  loadLocale?: LoadLocale
  saveLocale?: SaveLocale
}>(), {
  loadAppearance: async (): Promise<AppearanceState> => isTauri()
    ? loadBootstrap()
    : { theme: 'dark' },
  saveAppearance: async (theme: AppTheme): Promise<void> => {
    if (isTauri()) await saveTheme(theme)
  },
  loadLocale: async (): Promise<{ locale: Locale }> => isTauri()
    ? loadOwnedLocaleSetting()
    : { locale: 'en' },
  saveLocale: async (locale: Locale): Promise<void> => {
    if (isTauri()) await saveOwnedLocaleSetting(locale)
  },
})

const selected = ref<AppTheme | null>(null)
const loading = ref(true)
const unavailable = ref(false)
const saveFailed = ref(false)
const selectedLocale = ref<Locale | null>(null)
const localeSaveFailed = ref(false)

onMounted(async () => {
  try {
    const value = await props.loadAppearance()
    selected.value = value.theme
    appTheme.value = value.theme
    const locale = await props.loadLocale()
    selectedLocale.value = locale.locale
    currentLocale.value = locale.locale
  }
  catch {
    unavailable.value = true
  }
  finally {
    loading.value = false
  }
})

async function selectTheme(theme: AppTheme) {
  const previous = selected.value
  selected.value = theme
  appTheme.value = theme
  saveFailed.value = false
  try {
    await props.saveAppearance(theme)
  }
  catch {
    selected.value = previous
    if (previous !== null) appTheme.value = previous
    saveFailed.value = true
  }
}

async function selectLocale(locale: Locale) {
  const previous = selectedLocale.value
  selectedLocale.value = locale
  currentLocale.value = locale
  localeSaveFailed.value = false
  try {
    await props.saveLocale(locale)
  }
  catch {
    selectedLocale.value = previous
    if (previous !== null) currentLocale.value = previous
    localeSaveFailed.value = true
  }
}

function onLocaleChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  if (value === 'en' || value === 'ru') void selectLocale(value)
}
</script>

<template>
  <section aria-labelledby="appearance-title">
    <header class="page-header">
      <div>
        <h1 id="appearance-title">{{ translate('appearance.title') }}</h1>
        <p>{{ translate('appearance.description') }}</p>
      </div>
    </header>
    <nav class="page-subnav" :aria-label="translate('settings.title')">
      <RouterLink to="/settings/runtimes">Runtime</RouterLink>
      <RouterLink to="/settings/appearance">{{ translate('appearance.title') }}</RouterLink>
      <RouterLink to="/settings/diagnostics">Diagnostics</RouterLink>
    </nav>

    <div v-if="loading" class="empty-state" aria-live="polite">
      <h2>{{ translate('appearance.loading') }}</h2>
    </div>
    <GcAlert v-else-if="unavailable" level="error" :title="translate('appearance.unavailable')" role="alert">
      {{ translate('appearance.unavailableMessage') }}
    </GcAlert>
    <template v-else>
      <GcAlert v-if="saveFailed" level="error" :title="translate('appearance.saveFailed')" role="alert">
        {{ translate('appearance.previousTheme') }}
      </GcAlert>
      <GcAlert v-if="localeSaveFailed" level="error" :title="translate('appearance.localeSaveFailed')" role="alert">
        {{ translate('appearance.previousLocale') }}
      </GcAlert>
      <fieldset class="appearance-options">
        <legend>{{ translate('appearance.theme') }}</legend>
        <label>
          <input type="radio" name="theme" value="dark" :checked="selected === 'dark'" @change="selectTheme('dark')">
          {{ translate('appearance.darkTheme') }}
        </label>
        <label>
          <input type="radio" name="theme" value="light" :checked="selected === 'light'" @change="selectTheme('light')">
          {{ translate('appearance.lightTheme') }}
        </label>
      </fieldset>
      <label class="appearance-locale">
        <span>{{ translate('appearance.language') }}</span>
        <select
          name="locale"
          :value="selectedLocale ?? 'en'"
          @change="onLocaleChange"
        >
          <option value="en">{{ translate('appearance.english') }}</option>
          <option value="ru">{{ translate('appearance.russian') }}</option>
        </select>
      </label>
      <p class="appearance-status" role="status">
        {{ selected === 'light' ? translate('appearance.lightEnabled') : translate('appearance.darkEnabled') }}
      </p>
    </template>
  </section>
</template>
