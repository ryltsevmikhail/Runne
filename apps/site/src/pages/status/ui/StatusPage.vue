<script setup lang="ts">
import { computed } from "vue";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";
import WaitlistSection from "../../../shared/ui/waitlist/WaitlistSection.vue";

const snapshotIcons = ["▣", "▤", "▢", "♢"];
const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.status);
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
      </p><h3>{{ copy.hero.panelTitle }}</h3>
      <p>{{ copy.hero.panelBody }}</p><p class="tag">
        {{ copy.hero.platform }}
      </p>
    </aside>
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            {{ copy.snapshot.eyebrow }}
          </p><h2>{{ copy.snapshot.heading }}</h2>
        </div>
        <p>{{ copy.snapshot.lead }}</p>
      </div>
      <div class="cards four">
        <article
          v-for="(card, index) in copy.snapshot.cards"
          :key="card.title"
          class="card"
        >
          <span class="icon green">{{ snapshotIcons[index] }}</span><h3>{{ card.title }}</h3><p>{{ card.body }}</p>
        </article>
      </div>
    </div>
  </section>
  <section>
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow violet">
            {{ copy.boundaries.eyebrow }}
          </p><h2>{{ copy.boundaries.heading }}</h2>
        </div>
        <p>{{ copy.boundaries.lead }}</p>
      </div>
      <div class="status-columns">
        <div class="outline-panel green">
          <p class="status-dot">
            {{ copy.boundaries.current.label }}
          </p><h3>{{ copy.boundaries.current.title }}</h3>
          <ul class="verified-list">
            <li
              v-for="item in copy.boundaries.current.items"
              :key="item"
            >
              {{ item }}
            </li>
          </ul>
        </div>
        <div class="outline-panel violet">
          <p class="status-dot violet">
            {{ copy.boundaries.open.label }}
          </p><h3>{{ copy.boundaries.open.title }}</h3>
          <ul class="target-list">
            <li
              v-for="item in copy.boundaries.open.items"
              :key="item"
            >
              {{ item }}
            </li>
          </ul>
        </div>
      </div>
    </div>
  </section>
  <section class="surface">
    <div class="section split">
      <div>
        <p class="eyebrow">
          {{ copy.platforms.eyebrow }}
        </p><h2>{{ copy.platforms.heading }}</h2>
        <p class="lede">
          {{ copy.platforms.lead }}
        </p>
      </div>
      <ul class="platforms">
        <li
          v-for="(item, index) in copy.platforms.items"
          :key="item.name"
        >
          {{ item.name }} <span :class="index > 0 ? 'violet' : ''">{{ item.status }}</span>
        </li>
      </ul>
    </div>
  </section>
  <WaitlistSection />
</template>
