<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";
import WaitlistSection from "../../../shared/ui/waitlist/WaitlistSection.vue";

const trustIcons = ["▣", "⌘", "▤"];
const trustTones = ["", "violet", "green"];
const mechanismIcons = ["⌘", "♧", "⊠", "⌘", "⌁", "⌁"];
const mechanismTones = ["green", "", "coral", "violet", "green", ""];
const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.security);
</script>

<template>
  <section class="page-hero">
    <span class="rail-dot coral" /><div>
      <p class="eyebrow coral">
        {{ copy.hero.eyebrow }}
      </p><h1>{{ copy.hero.heading }}</h1><p>{{ copy.hero.lead }}</p>
    </div>
    <aside class="signal-panel">
      <p
        class="icon green"
        style="font-size: 3.3rem; text-align: center"
      >
        ♢
      </p>
      <p
        class="eyebrow"
        style="color: var(--warm-white); text-align: center"
      >
        {{ copy.hero.panelEyebrow }}
      </p>
      <p style="text-align: center">
        {{ copy.hero.panelBody }}
      </p>
    </aside>
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow green">
            {{ copy.trust.eyebrow }}
          </p><h2>{{ copy.trust.heading }}</h2>
        </div>
        <p>{{ copy.trust.lead }}</p>
      </div>
      <div class="cards">
        <article
          v-for="(card, index) in copy.trust.cards"
          :key="card.title"
          class="card"
        >
          <span
            class="icon"
            :class="trustTones[index]"
          >{{ trustIcons[index] }}</span>
          <h3>{{ card.title }}</h3><p>{{ card.body }}</p>
          <p
            class="tag"
            :class="index === 0 ? 'coral' : index === 1 ? 'violet' : ''"
          >
            {{ card.label }}
          </p>
        </article>
      </div>
    </div>
  </section>
  <section>
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            {{ copy.mechanisms.eyebrow }}
          </p><h2>{{ copy.mechanisms.heading }}</h2>
        </div>
        <p>{{ copy.mechanisms.lead }}</p>
      </div>
      <div class="cards">
        <article
          v-for="(card, index) in copy.mechanisms.cards"
          :key="card.title"
          class="card"
        >
          <span
            class="icon"
            :class="mechanismTones[index]"
          >{{ mechanismIcons[index] }}</span>
          <h3>{{ card.title }}</h3><p>{{ card.body }}</p>
        </article>
      </div>
    </div>
  </section>
  <section class="surface">
    <div class="section split">
      <div>
        <p class="eyebrow violet">
          {{ copy.boundary.eyebrow }}
        </p><h2>{{ copy.boundary.heading }}</h2>
        <p class="lede">
          {{ copy.boundary.lead }}
        </p>
      </div>
      <div>
        <ol class="list-rows">
          <li
            v-for="item in copy.boundary.items"
            :key="item"
          >
            <b>{{ item }}</b>
          </li>
        </ol>
        <RouterLink
          class="button"
          :to="{ name: 'roadmap' }"
        >
          {{ copy.boundary.roadmapCta }} <span aria-hidden="true">→</span>
        </RouterLink>
      </div>
    </div>
  </section>
  <WaitlistSection />
</template>
