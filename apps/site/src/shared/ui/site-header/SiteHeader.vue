<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { localeMetadata } from "../../lib/i18n/locales";
import { localeCodes, type Locale } from "../../lib/i18n/types";
import { useSiteI18n } from "../../lib/i18n/useSiteI18n";

const navPages = ["product", "architecture", "security", "roadmap", "status"] as const;
const { dictionary, locale, setLocale } = useSiteI18n();
const copy = computed(() => dictionary.value.shared);
const selectedLocale = computed({
  get: () => locale.value,
  set: (value: Locale) => setLocale(value),
});
</script>

<template>
  <a
    class="skip-link"
    href="#main"
  >{{ copy.skipToContent }}</a>
  <header class="site-header">
    <RouterLink
      class="brand"
      :to="{ name: 'home' }"
      :aria-label="copy.homeAriaLabel"
    >
      <img
        src="/brand/gocode-lockup-compact.png"
        width="140"
        height="28"
        alt="GOCODE"
      >
    </RouterLink>
    <nav :aria-label="copy.primaryNavAriaLabel">
      <ul>
        <li
          v-for="navPage in navPages"
          :key="navPage"
        >
          <RouterLink :to="{ name: navPage }">
            {{ copy.nav[navPage] }}
          </RouterLink>
        </li>
      </ul>
    </nav>
    <label class="language-switcher">
      <span class="visually-hidden">{{ copy.languageLabel }}</span>
      <select
        v-model="selectedLocale"
        :aria-label="copy.languageLabel"
      >
        <option
          v-for="option in localeCodes"
          :key="option"
          :value="option"
        >
          {{ localeMetadata[option].nativeName }}
        </option>
      </select>
    </label>
    <RouterLink
      class="button button-small"
      :to="{ name: 'home', hash: '#waitlist' }"
    >
      {{ copy.waitlistCta }}
    </RouterLink>
  </header>
</template>
