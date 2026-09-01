<script setup lang="ts">
import { cta } from "../content";
</script>

<template>
  <section id="cta" class="open-cta">
    <div class="wrap cta-row">
      <div>
        <h2>{{ cta.headline }}</h2>
        <p>{{ cta.body }}</p>
      </div>
      <div class="cta-actions">
        <a class="btn btn-black" href="#top">
          <span>Read the docs</span>
          <span class="btn-arrow" aria-hidden="true">↗</span>
        </a>
        <a class="cta-link" href="https://github.com" rel="noopener">View on GitHub →</a>
      </div>
    </div>
  </section>
</template>
