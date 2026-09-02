<script setup lang="ts">
import { useSite } from "../useSite";
const { c } = useSite();
</script>

<template>
  <footer class="site-footer">
    <div class="wrap">
      <div class="footer-main">
        <div>
          <img class="footer-logo" src="/brand/runne-logo.png" width="152" height="34" alt="Runne.">
          <p class="footer-proposition">{{ c.footer.proposition }}</p>
        </div>
        <nav class="footer-cols" aria-label="Footer">
          <div v-for="column in c.footer.columns" :key="column.heading">
            <p class="col-label">{{ column.heading }}</p>
            <ul>
              <li v-for="link in column.links" :key="link"><a href="#top">{{ link }}</a></li>
            </ul>
          </div>
        </nav>
      </div>
      <div class="footer-meta">
        <p class="mono">{{ c.footer.copyright }}</p>
        <p class="mono status"><i aria-hidden="true" />{{ c.footer.status }}</p>
      </div>
    </div>
  </footer>
</template>
