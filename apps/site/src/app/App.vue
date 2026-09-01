<script setup lang="ts">
import SiteNav from "./ui/SiteNav.vue";
import HeroSection from "./ui/HeroSection.vue";
import FieldNotes from "./ui/FieldNotes.vue";
import LiveDemo from "./ui/LiveDemo.vue";
import ContractFlow from "./ui/ContractFlow.vue";
import OpenCta from "./ui/OpenCta.vue";
import SiteFooter from "./ui/SiteFooter.vue";
import NotFound from "./ui/NotFound.vue";

defineProps<{ notFound?: boolean }>();
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
