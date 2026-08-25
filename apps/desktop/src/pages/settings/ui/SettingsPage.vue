<script setup lang="ts">
import { unavailableSettingsPageAdapter, type SettingsPageAdapter } from '../model/page-state'
import SettingsStatePage from './SettingsStatePage.vue'

const props = withDefaults(defineProps<{
  readonly adapter?: SettingsPageAdapter
}>(), {
  adapter: () => unavailableSettingsPageAdapter('Settings'),
})
</script>

<template>
  <SettingsStatePage
    title="Settings"
    title-key="settings.title"
    :adapter="props.adapter"
  />
</template>
