<script setup lang="ts">
import { computed, provide } from "vue";
import { ContentKey, LangKey, contents, langOf, type Lang } from "./content";
import SiteNav from "./ui/SiteNav.vue";
import HeroSection from "./ui/HeroSection.vue";
import FieldNotes from "./ui/FieldNotes.vue";
import LiveDemo from "./ui/LiveDemo.vue";
import ContractFlow from "./ui/ContractFlow.vue";
import OpenCta from "./ui/OpenCta.vue";
import SiteFooter from "./ui/SiteFooter.vue";
import NotFound from "./ui/NotFound.vue";

const props = defineProps<{ notFound?: boolean; path?: string }>();
const lang = computed<Lang>(() => langOf(props.path ?? "/"));

provide(LangKey, lang.value);
provide(ContentKey, contents[lang.value]);
</script>

<template>
  <a class="skip-link" href="#main">Skip to content</a>
  <SiteNav />
  <main
    id="main"
    tabindex="-1"
  >
    <NotFound v-if="notFound" />
    <template v-else>
      <HeroSection />
      <FieldNotes />
      <LiveDemo />
      <ContractFlow />
      <OpenCta />
    </template>
  </main>
  <SiteFooter />
</template>
