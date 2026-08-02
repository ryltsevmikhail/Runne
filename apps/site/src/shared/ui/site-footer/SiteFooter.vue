<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { useSiteI18n } from "../../lib/i18n/useSiteI18n";

const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.shared);
</script>

<template>
  <footer class="site-footer">
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
    <p>{{ copy.footer.description }}</p>
    <nav :aria-label="copy.footerNavAriaLabel">
      <RouterLink :to="{ name: 'privacy' }">
        {{ copy.footer.privacy }}
      </RouterLink>
      <RouterLink :to="{ name: 'status' }">
        {{ copy.nav.status }}
      </RouterLink>
      <RouterLink :to="{ name: 'roadmap' }">
        {{ copy.nav.roadmap }}
      </RouterLink>
    </nav>
    <small>{{ copy.footer.preview }}</small>
  </footer>
</template>
