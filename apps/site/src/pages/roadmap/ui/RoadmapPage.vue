<script setup lang="ts">
import { computed } from "vue";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";
import WaitlistSection from "../../../shared/ui/waitlist/WaitlistSection.vue";

const stageColors = ["var(--green)", "var(--orange)", "var(--violet)"];
const legendClasses = ["status-dot", "tag", "status-dot violet"];
const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.roadmap);

function stageBody(body: string) {
  const [summary, evidence] = body.split("\n");
  return { summary, evidence };
}
</script>

<template>
  <section class="page-hero">
    <span class="rail-dot violet" /><div>
      <p class="eyebrow violet">
        {{ copy.hero.eyebrow }}
      </p><h1>{{ copy.hero.heading }}</h1><p>{{ copy.hero.lead }}</p>
    </div>
    <aside class="signal-panel violet">
      <p class="status-dot violet">
        {{ copy.hero.panelLabel }}
      </p><h3>{{ copy.hero.panelTitle }}</h3>
      <p>{{ copy.hero.panelBody }}</p><div class="bubble">
        {{ copy.hero.warning }}
      </div>
    </aside>
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            {{ copy.stages.eyebrow }}
          </p><h2>{{ copy.stages.heading }}</h2>
        </div>
        <p>{{ copy.stages.lead }}</p>
      </div>
      <div class="cards">
        <article
          v-for="(card, index) in copy.stages.cards"
          :key="card.title"
          class="card"
          :style="{ borderTop: `3px solid ${stageColors[index]}` }"
        >
          <p class="tag">
            {{ card.label }}
          </p><h3>{{ card.title }}</h3>
          <p>{{ stageBody(card.body).summary }}</p>
          <p
            v-if="stageBody(card.body).evidence"
            class="tag"
          >
            {{ stageBody(card.body).evidence }}
          </p>
        </article>
      </div>
    </div>
  </section>
  <section>
    <div class="section split">
      <div>
        <p class="eyebrow coral">
          {{ copy.exclusions.eyebrow }}
        </p><h2>{{ copy.exclusions.heading }}</h2>
      </div>
      <ol class="list-rows">
        <li
          v-for="item in copy.exclusions.items"
          :key="item.title"
        >
          <b>{{ item.title }}</b><span>{{ item.body }}</span>
        </li>
      </ol>
    </div>
  </section>
  <section class="surface">
    <div class="section">
      <p class="eyebrow violet">
        {{ copy.legend.eyebrow }}
      </p><h2>{{ copy.legend.heading }}</h2>
      <div class="cards">
        <article
          v-for="(card, index) in copy.legend.cards"
          :key="card.label"
          class="card"
        >
          <p
            :class="legendClasses[index]"
            :style="index === 1 ? { color: 'var(--orange)' } : undefined"
          >
            {{ card.label }}
          </p>
          <p>{{ card.body }}</p>
        </article>
      </div>
    </div>
  </section>
  <WaitlistSection />
</template>
