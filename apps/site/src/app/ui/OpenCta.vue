<script setup lang="ts">
import { useSite } from "../useSite";
const { c } = useSite();
</script>

<template>
  <section id="cta" class="open-cta">
    <div class="wrap cta-row">
      <div>
        <h2>{{ c.cta.headline }}</h2>
        <p>{{ c.cta.body }}</p>
      </div>
      <div class="cta-actions">
        <a class="btn btn-black" href="#top">
          <span>{{ c.cta.docs }}</span>
          <span class="btn-arrow" aria-hidden="true">↗</span>
        </a>
        <a class="cta-link" href="https://github.com" rel="noopener">{{ c.cta.github }}</a>
      </div>
    </div>
  </section>
</template>
