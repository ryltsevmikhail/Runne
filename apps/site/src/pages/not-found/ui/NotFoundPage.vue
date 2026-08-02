<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";

const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.shared.notFound);
</script>

<template>
  <section class="page-hero not-found">
    <span class="rail-dot coral" /><div>
      <p class="eyebrow coral">
        {{ copy.eyebrow }}
      </p><h1>{{ copy.heading }}</h1><p>{{ copy.body }}</p>
      <RouterLink
        class="button"
        :to="{ name: 'home' }"
      >
        {{ copy.backHome }} <span aria-hidden="true">→</span>
      </RouterLink>
    </div>
  </section>
</template>
