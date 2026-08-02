<script setup lang="ts">
import { computed } from "vue";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";

const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.privacy);
</script>

<template>
  <section class="page-hero">
    <span class="rail-dot green" /><div>
      <p class="eyebrow green">
        {{ copy.hero.eyebrow }}
      </p><h1>{{ copy.hero.heading }}</h1><p>{{ copy.hero.lead }}</p>
    </div>
    <aside class="signal-panel green">
      <p class="status-dot">
        {{ copy.hero.panelLabel }}
      </p><h3>{{ copy.hero.panelTitle }}</h3><p>{{ copy.hero.panelBody }}</p>
    </aside>
  </section>
  <section class="surface">
    <div class="section split">
      <div>
        <p class="eyebrow">
          {{ copy.boundary.eyebrow }}
        </p><h2>{{ copy.boundary.heading }}</h2>
      </div>
      <ol class="list-rows">
        <li
          v-for="item in copy.boundary.items"
          :key="item.title"
        >
          <b>{{ item.title }}</b><span>{{ item.body }}</span>
        </li>
      </ol>
    </div>
  </section>
</template>
