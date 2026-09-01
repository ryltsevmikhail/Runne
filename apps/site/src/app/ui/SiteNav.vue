<script setup lang="ts">
import { navLinks } from "../content";
</script>

<template>
  <header class="site-nav">
    <div class="wrap nav-row">
      <a class="brand" href="#top" aria-label="Runne home">
        <img src="/brand/runne-logo.png" width="152" height="34" alt="Runne.">
      </a>
      <nav aria-label="Primary">
        <ul class="nav-links">
          <li v-for="link in navLinks" :key="link.href">
            <a :href="link.href">{{ link.label }}</a>
          </li>
        </ul>
      </nav>
      <a class="btn btn-cobalt" href="#cta">
        <span class="btn-arrow" aria-hidden="true">→</span>
        <span>Read the docs</span>
      </a>
    </div>
  </header>
</template>
