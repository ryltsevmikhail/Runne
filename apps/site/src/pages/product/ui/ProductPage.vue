<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { useSiteI18n } from "../../../shared/lib/i18n/useSiteI18n";
import ProductMockup from "../../../shared/ui/product-mockup/ProductMockup.vue";
import WaitlistSection from "../../../shared/ui/waitlist/WaitlistSection.vue";

const itemIcons = ["▱", "▢", "⌁"];
const itemTones = ["", "green", "violet"];
const { dictionary } = useSiteI18n();
const copy = computed(() => dictionary.value.pages.product);
</script>

<template>
  <section class="page-hero">
    <span class="rail-dot" /><div>
      <p class="eyebrow">
        {{ copy.hero.eyebrow }}
      </p><h1>{{ copy.hero.heading }}</h1>
      <p>{{ copy.hero.lead }}</p>
      <div class="outline-panel violet">
        <span class="status-dot violet">{{ copy.hero.boundary }}</span>
      </div>
      <RouterLink
        class="button"
        :to="{ name: 'home', hash: '#waitlist' }"
      >
        {{ copy.hero.cta }} <span aria-hidden="true">↗</span>
      </RouterLink>
    </div><ProductMockup :copy="copy.hero.mockup" />
  </section>
  <section class="surface">
    <div class="section">
      <div class="section-heading">
        <div>
          <p class="eyebrow green">
            {{ copy.workflow.eyebrow }}
          </p><h2>{{ copy.workflow.heading }}</h2>
        </div>
        <p>{{ copy.workflow.lead }}</p>
      </div>
      <div class="process">
        <article
          v-for="(step, index) in copy.workflow.steps"
          :key="step.title"
        >
          <strong>0{{ index + 1 }}</strong><h3>{{ step.title }}</h3><p>{{ step.body }}</p>
        </article>
      </div>
    </div>
  </section>
  <section>
    <div class="section split">
      <div>
        <p class="eyebrow violet">
          {{ copy.workspace.eyebrow }}
        </p><h2>{{ copy.workspace.heading }}</h2>
        <p class="lede">
          {{ copy.workspace.lead }}
        </p>
      </div>
      <ol class="list-rows">
        <li
          v-for="(item, index) in copy.workspace.items"
          :key="item.title"
        >
          <b><span
            class="icon"
            :class="itemTones[index]"
          >{{ itemIcons[index] }}</span> {{ item.title }}</b>
          <span>{{ item.body }}</span>
        </li>
      </ol>
    </div>
  </section>
  <WaitlistSection />
</template>
