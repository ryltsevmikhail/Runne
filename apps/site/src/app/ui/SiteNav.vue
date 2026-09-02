<script setup lang="ts">
import { useSite, langPath } from "../useSite";
const { c } = useSite();
</script>

<template>
  <header class="site-nav">
    <div class="wrap nav-row">
      <a class="brand" href="#top" aria-label="Runne home">
        <img src="/brand/runne-logo.png" width="152" height="34" alt="Runne.">
      </a>
      <nav aria-label="Primary">
        <ul class="nav-links">
          <li v-for="link in c.navLinks" :key="link.href">
            <a :href="link.href">{{ link.label }}</a>
          </li>
        </ul>
      </nav>
      <div class="nav-actions">
        <a class="lang-switch" :href="langPath(c.langSwitch.to)">{{ c.langSwitch.label }}</a>
        <a class="btn btn-cobalt" href="#cta">
          <span class="btn-arrow" aria-hidden="true">→</span>
          <span>{{ c.docsLabel }}</span>
        </a>
      </div>
    </div>
  </header>
</template>
