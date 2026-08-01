<script setup lang="ts">
import { toRef } from "vue";
import { RouterView, useRoute } from "vue-router";
import SiteFooter from "../shared/ui/site-footer/SiteFooter.vue";
import SiteHeader from "../shared/ui/site-header/SiteHeader.vue";
import { usePageMetadata } from "./lib/usePageMetadata";

const route = useRoute();
usePageMetadata(toRef(() => route));
</script>

<template>
  <SiteHeader />
  <main
    id="main"
    tabindex="-1"
  >
    <RouterView />
  </main>
  <SiteFooter />
</template>
