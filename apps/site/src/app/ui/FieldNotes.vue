<script setup lang="ts">
import { comic } from "../content";
</script>

<template>
  <section id="capabilities" class="field-notes">
    <div class="wrap">
      <header class="notes-head">
        <p class="eyebrow cobalt">{{ comic.eyebrow }}</p>
        <h2>{{ comic.headline }}</h2>
        <p class="lead">{{ comic.intro }}</p>
        <ul class="chip-row">
          <li v-for="chip in comic.chips" :key="chip">{{ chip }}</li>
        </ul>
      </header>

      <div class="panel-grid">
        <article v-for="panel in comic.panels" :key="panel.n" class="panel-card">
          <div class="panel-art">
            <img :src="panel.image" width="360" height="300" :alt="`Runne mascot: ${panel.kicker.toLowerCase()}`">
            <p class="speech" :class="`speech-${panel.n}`">{{ panel.speech }}</p>
          </div>
          <div class="panel-caption">
            <div class="caption-top">
              <span class="num-chip">{{ panel.n }}</span>
              <span class="kicker">{{ panel.kicker }}</span>
            </div>
            <h3>{{ panel.title }}</h3>
            <p>{{ panel.body }}</p>
          </div>
        </article>
      </div>

      <div class="closing-band">
        <div>
          <h3>{{ comic.closing.headline }}</h3>
          <p class="mono">{{ comic.closing.detail }}</p>
        </div>
        <span class="closing-arrow" aria-hidden="true">→</span>
      </div>

      <div id="philosophy" class="guarantees">
        <div class="guarantees-head">
          <h3>{{ comic.guarantees.headline }}</h3>
          <p class="eyebrow cobalt">{{ comic.guarantees.eyebrow }}</p>
        </div>
        <ol class="guarantee-list">
          <li v-for="item in comic.guarantees.items" :key="item.n">
            <span class="g-num">{{ item.n }}</span>
            <strong>{{ item.name }}</strong>
            <p>{{ item.body }}</p>
          </li>
        </ol>
      </div>

      <header class="notes-head chapter2">
        <p class="eyebrow cobalt">{{ comic.chapter2.eyebrow }}</p>
        <h2>{{ comic.chapter2.headline }}</h2>
        <p class="lead">{{ comic.chapter2.intro }}</p>
      </header>

      <div class="chapter2-grid">
        <article class="panel-card">
          <div class="panel-art">
            <span class="runtime-tag">{{ comic.chapter2.panels[0].runtimeLabel }}</span>
            <img src="/mascots/hero-run.png" width="360" height="300" alt="Runne mascot serving many clients">
            <p class="speech speech-07">{{ comic.chapter2.panels[0].speech }}</p>
          </div>
          <div class="panel-caption">
            <div class="caption-top">
              <span class="num-chip">{{ comic.chapter2.panels[0].n }}</span>
              <span class="kicker">{{ comic.chapter2.panels[0].kicker }}</span>
            </div>
            <h3>{{ comic.chapter2.panels[0].title }}</h3>
            <p>{{ comic.chapter2.panels[0].body }}</p>
          </div>
        </article>

        <article class="panel-card">
          <div class="panel-art">
            <div class="budget-monitor" aria-hidden="true">
              <p class="budget-head">{{ comic.chapter2.budget.header }}</p>
              <div v-for="row in comic.chapter2.budget.rows" :key="row.label" class="budget-row">
                <span>{{ row.label }}</span>
                <i class="budget-bar"><b :style="{ width: row.pct + '%' }" /></i>
                <em>{{ row.value }}</em>
              </div>
              <p class="budget-limit">{{ comic.chapter2.budget.limit }}</p>
            </div>
            <img src="/mascots/budget-guard.png" width="360" height="300" alt="Runne mascot guarding the run budget">
            <p class="speech speech-09">{{ comic.chapter2.panels[1].speech }}</p>
          </div>
          <div class="panel-caption">
            <div class="caption-top">
              <span class="num-chip">{{ comic.chapter2.panels[1].n }}</span>
              <span class="kicker">{{ comic.chapter2.panels[1].kicker }}</span>
            </div>
            <h3>{{ comic.chapter2.panels[1].title }}</h3>
            <p>{{ comic.chapter2.panels[1].body }}</p>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
