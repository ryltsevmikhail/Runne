<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";
import ProductMockup from "../../../shared/ui/product-mockup/ProductMockup.vue";
import WaitlistSection from "../../../shared/ui/waitlist/WaitlistSection.vue";

const flowIcons = ["▣", "⌁", "{ }", "◉", "▤"];
const roadmapTones = ["", "", "violet"];
const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.home);
</script>

<template>
  <section class="page-hero">
    <span class="rail-dot green" />
    <div>
      <p class="eyebrow green">
        {{ copy.hero.eyebrow }}
      </p>
      <h1>{{ copy.hero.heading }}</h1>
      <p>{{ copy.hero.lead }}</p>
      <RouterLink
        class="button"
        :to="{ name: 'home', hash: '#waitlist' }"
      >
        {{ copy.hero.cta }} <span aria-hidden="true">↗</span>
      </RouterLink>
    </div>
    <ProductMockup :copy="copy.hero.mockup" />
  </section>
  <section class="surface">
    <div class="section split">
      <div>
        <p class="eyebrow">
          {{ copy.why.eyebrow }}
        </p>
        <h2>{{ copy.why.heading }}</h2>
        <p class="lede">
          {{ copy.why.lead }}
        </p>
      </div>
      <ol class="list-rows">
        <li
          v-for="item in copy.why.items"
          :key="item.title"
        >
          <b>{{ item.title }}</b><span>{{ item.body }}</span>
        </li>
      </ol>
    </div>
  </section>
  <section>
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow green">
            {{ copy.architecture.eyebrow }}
          </p>
          <h2>{{ copy.architecture.heading }}</h2>
        </div>
        <p>{{ copy.architecture.lead }}</p>
      </div>
      <div class="flow">
        <div
          v-for="(item, index) in copy.architecture.flow"
          :key="item.title"
        >
          <span
            class="icon"
            :class="index === 1 || index === 4 ? 'green' : index === 2 ? 'violet' : ''"
          >{{ flowIcons[index] }}</span>
          <b>{{ item.title }}</b><small>{{ item.body }}</small>
        </div>
      </div>
    </div>
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow violet">
            {{ copy.preview.eyebrow }}
          </p>
          <h2>{{ copy.preview.heading }}</h2>
        </div>
        <p>{{ copy.preview.lead }}</p>
      </div>
      <div class="status-columns">
        <div class="outline-panel green">
          <p class="status-dot">
            {{ copy.preview.verified.label }}
          </p>
          <h3>{{ copy.preview.verified.title }}</h3>
          <ul class="verified-list">
            <li
              v-for="item in copy.preview.verified.items"
              :key="item"
            >
              {{ item }}
            </li>
          </ul>
        </div>
        <div class="outline-panel violet">
          <p class="status-dot violet">
            {{ copy.preview.review.label }}
          </p>
          <h3>{{ copy.preview.review.title }}</h3>
          <ul class="target-list">
            <li
              v-for="item in copy.preview.review.items"
              :key="item"
            >
              {{ item }}
            </li>
          </ul>
        </div>
      </div>
    </div>
  </section>
  <section>
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow violet">
            {{ copy.roadmap.eyebrow }}
          </p>
          <h2>{{ copy.roadmap.heading }}</h2>
        </div>
        <p>{{ copy.roadmap.lead }}</p>
      </div>
      <div class="cards">
        <article
          v-for="(card, index) in copy.roadmap.cards"
          :key="card.title"
          class="card"
        >
          <p
            class="tag"
            :class="roadmapTones[index]"
          >
            {{ card.label }}
          </p>
          <h3>{{ card.title }}</h3><p>{{ card.body }}</p>
        </article>
      </div>
    </div>
  </section>
  <WaitlistSection />
</template>
