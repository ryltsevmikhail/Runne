<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { useSiteI18n } from "../../lib/i18n/useSiteI18n";

const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.shared.waitlist);
</script>

<template>
  <section
    id="waitlist"
    class="waitlist"
    aria-labelledby="waitlist-title"
  >
    <div>
      <p class="eyebrow">
        {{ copy.eyebrow }}
      </p>
      <h2 id="waitlist-title">
        {{ copy.heading }}
      </h2>
      <p>{{ copy.body }}</p>
    </div>
    <RouterLink
      class="button"
      :to="{ name: 'status' }"
    >
      {{ copy.statusLink }} <span aria-hidden="true">↗</span>
    </RouterLink>
  </section>
</template>
