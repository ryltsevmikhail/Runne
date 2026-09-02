<script setup lang="ts">
import { useSite } from "../useSite";
const { c, lang } = useSite();
const art = (n: string, kind: "desk" | "mob") => `/mascots/${kind}-${lang}-${n}.jpg`;
</script>

<template>
  <section id="capabilities" class="field-notes">
    <div class="wrap">
      <header class="notes-head">
        <p class="eyebrow cobalt">{{ c.comic.eyebrow }}</p>
        <h2>{{ c.comic.headline }}</h2>
        <p class="lead">{{ c.comic.intro }}</p>
        <ul class="chip-row">
          <li v-for="chip in c.comic.chips" :key="chip">{{ chip }}</li>
        </ul>
      </header>

      <div class="panel-grid">
        <article v-for="panel in c.comic.panels" :key="panel.n" class="panel-card">
          <div class="panel-art">
            <img class="art-desktop" :src="art(panel.n, 'desk')" alt="" loading="lazy" decoding="async">
            <img class="art-mobile" :src="art(panel.n, 'mob')" alt="" loading="lazy" decoding="async">
          </div>
          <div class="panel-caption">
            <p class="caption-line">{{ panel.n }} · {{ panel.kicker }}</p>
            <h3>{{ panel.title }}</h3>
            <p class="cap-body">{{ panel.body }}</p>
          </div>
        </article>
      </div>

      <div class="closing-band">
        <div>
          <h3>{{ c.comic.closing.headline }}</h3>
          <p class="mono">{{ c.comic.closing.detail }}</p>
        </div>
        <span class="closing-arrow" aria-hidden="true">→</span>
      </div>

      <div id="philosophy" class="guarantees">
        <div class="guarantees-head">
          <h3>{{ c.comic.guarantees.headline }}</h3>
          <p class="eyebrow cobalt">{{ c.comic.guarantees.eyebrow }}</p>
        </div>
        <ol class="guarantee-list">
          <li v-for="item in c.comic.guarantees.items" :key="item.n">
            <span class="g-num">{{ item.n }}</span>
            <strong>{{ item.name }}</strong>
            <p>{{ item.body }}</p>
          </li>
        </ol>
      </div>

      <header class="notes-head chapter2">
        <p class="eyebrow cobalt">{{ c.comic.chapter2.eyebrow }}</p>
        <h2>{{ c.comic.chapter2.headline }}</h2>
        <p class="lead">{{ c.comic.chapter2.intro }}</p>
      </header>

      <div class="chapter2-grid">
        <article v-for="panel in c.comic.chapter2.panels" :key="panel.n" class="panel-card">
          <div class="panel-art">
            <img class="art-desktop" :src="art(panel.n, 'desk')" alt="" loading="lazy" decoding="async">
            <img class="art-mobile" :src="art(panel.n, 'mob')" alt="" loading="lazy" decoding="async">
          </div>
          <div class="panel-caption">
            <p class="caption-line">{{ panel.n }} · {{ panel.kicker }}</p>
            <h3>{{ panel.title }}</h3>
            <p class="cap-body">{{ panel.body }}</p>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
