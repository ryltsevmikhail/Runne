<script setup lang="ts">
import { computed } from "vue";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";
import WaitlistSection from "../../../shared/ui/waitlist/WaitlistSection.vue";

const heroIcons = ["▣", "{ }", "◉", "▤"];
const flowIcons = ["⌁", "⌘", "♧", "▤", "⊞"];
const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.architecture);
</script>

<template>
  <section class="page-hero">
    <span class="rail-dot green" /><div>
      <p class="eyebrow green">
        {{ copy.hero.eyebrow }}
      </p><h1>{{ copy.hero.heading }}</h1>
      <p>{{ copy.hero.lead }}</p>
      <div class="outline-panel green">
        <span class="status-dot">{{ copy.hero.status }}</span>
      </div>
    </div><aside class="cards">
      <article
        v-for="(card, index) in copy.hero.cards"
        :key="card.title"
        class="card"
      >
        <span
          class="icon"
          :class="index === 1 ? 'violet' : index > 1 ? 'green' : ''"
        >{{ heroIcons[index] }}</span>
        <h3>{{ card.title }}</h3><p
          class="tag"
          :class="index === 1 ? 'violet' : ''"
        >
          {{ card.body }}
        </p>
      </article>
    </aside>
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            {{ copy.flow.eyebrow }}
          </p><h2>{{ copy.flow.heading }}</h2>
        </div>
        <p>{{ copy.flow.lead }}</p>
      </div>
      <div class="flow">
        <div
          v-for="(item, index) in copy.flow.items"
          :key="item.title"
        >
          <span
            class="icon"
            :class="index === 1 ? 'violet' : index > 2 ? 'green' : ''"
          >{{ flowIcons[index] }}</span>
          <b>{{ item.title }}</b><small>{{ item.body }}</small>
        </div>
      </div>
    </div>
  </section>
  <section>
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
        <article class="outline-panel orange">
          <h3>{{ copy.boundary.desktop.title }}</h3><p>{{ copy.boundary.desktop.body }}</p>
          <span
            class="status-dot"
            style="color: var(--orange)"
          >{{ copy.boundary.desktop.status }}</span>
        </article>
        <p style="text-align: center; color: var(--muted); margin: 13px">
          ↓
        </p>
        <article class="outline-panel green">
          <h3>{{ copy.boundary.runtime.title }}</h3><p>{{ copy.boundary.runtime.body }}</p>
          <span class="status-dot">{{ copy.boundary.runtime.status }}</span>
        </article>
      </div>
    </div>
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow green">
            {{ copy.replay.eyebrow }}
          </p><h2>{{ copy.replay.heading }}</h2>
        </div>
        <p>{{ copy.replay.lead }}</p>
      </div>
      <div class="process">
        <article
          v-for="(step, index) in copy.replay.steps"
          :key="step.title"
        >
          <strong>0{{ index + 1 }}</strong><h3>{{ step.title }}</h3><p>{{ step.body }}</p>
        </article>
      </div>
    </div>
  </section>
  <WaitlistSection />
</template>
