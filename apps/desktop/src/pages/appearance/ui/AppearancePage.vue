<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref, watch } from 'vue'

import type { AppTheme } from '@/shared/model/theme'
import {
  appTheme,
  applyOwnerTheme,
  captureThemeRead,
  commitTheme,
  themeWritePending,
} from '@/shared/model/theme'
import type { BootstrapState, ThemeAcknowledgement } from '@/shared/api/platform/bootstrap'
import { loadBootstrap, saveTheme } from '@/shared/api/platform/bootstrap'
import { loadLocale as loadOwnedLocaleSetting, saveLocale as saveOwnedLocaleSetting, type Locale } from '@/shared/api/platform/locale'
import { translate } from '@/shared/i18n'
import {
  applyOwnerLocale,
  captureLocaleRead,
  commitLocale,
  currentLocale,
  localeWritePending,
} from '@/shared/model/locale'

type AppearanceState = Pick<BootstrapState, 'theme'>
type LoadAppearance = () => Promise<AppearanceState>
type SaveAppearance = (theme: AppTheme) => Promise<ThemeAcknowledgement>
type LoadLocale = () => Promise<{ locale: Locale }>
type SaveLocale = (locale: Locale) => Promise<{ locale: Locale }>

const props = withDefaults(defineProps<{
  loadAppearance?: LoadAppearance
  saveAppearance?: SaveAppearance
  loadLocale?: LoadLocale
  saveLocale?: SaveLocale
}>(), {
  loadAppearance: async (): Promise<AppearanceState> => isTauri()
    ? loadBootstrap()
    : { theme: appTheme.value },
  saveAppearance: async (theme: AppTheme): Promise<ThemeAcknowledgement> => {
    return isTauri() ? saveTheme(theme) : { theme }
  },
  loadLocale: async (): Promise<{ locale: Locale }> => isTauri()
    ? loadOwnedLocaleSetting()
    : { locale: 'en' },
  saveLocale: async (locale: Locale): Promise<{ locale: Locale }> => {
    return isTauri() ? saveOwnedLocaleSetting(locale) : { locale }
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
    const themeRead = captureThemeRead()
    const localeRead = captureLocaleRead()
    const value = await props.loadAppearance()
    applyOwnerTheme(value.theme, themeRead)
    selected.value = appTheme.value
    const locale = await props.loadLocale()
    applyOwnerLocale(locale.locale, localeRead)
    selectedLocale.value = currentLocale.value
  }
  catch {
    unavailable.value = true
  }
  finally {
    loading.value = false
  }
})

watch(appTheme, theme => { selected.value = theme })
watch(currentLocale, locale => { selectedLocale.value = locale })

async function selectTheme(theme: AppTheme) {
  if (theme === selected.value) return
  const previous = selected.value
  saveFailed.value = false
  try {
    const acknowledgement = await commitTheme(theme, props.saveAppearance)
    if (acknowledgement === null) return
    selected.value = acknowledgement.theme
  }
  catch {
    selected.value = previous
    saveFailed.value = true
  }
}

async function selectLocale(locale: Locale) {
  if (locale === selectedLocale.value) return
  localeSaveFailed.value = false
  try {
    const acknowledgement = await commitLocale(locale, props.saveLocale)
    if (acknowledgement !== null) selectedLocale.value = acknowledgement.locale
  }
  catch {
    selectedLocale.value = currentLocale.value
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
      <RouterLink to="/settings/runtimes">{{ translate('runtimeSettings.title') }}</RouterLink>
      <RouterLink to="/settings/appearance">{{ translate('appearance.title') }}</RouterLink>
      <RouterLink to="/settings/diagnostics">{{ translate('navigation.diagnostics') }}</RouterLink>
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
      <fieldset class="appearance-options" :aria-busy="themeWritePending" :disabled="themeWritePending">
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
      <fieldset class="appearance-locale" :aria-busy="localeWritePending" :disabled="localeWritePending">
        <label>
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
      </fieldset>
      <p class="appearance-status" role="status">
        {{ selected === 'light' ? translate('appearance.lightEnabled') : translate('appearance.darkEnabled') }}
      </p>
    </template>
  </section>
</template>
