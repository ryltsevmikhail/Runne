<script setup lang="ts">
import { useSite } from "../useSite";
const { c } = useSite();
</script>

<template>
  <section id="top" class="hero">
    <div class="wrap">
      <div class="hero-grid">
        <div class="hero-copy">
          <h1>{{ c.hero.headline }}</h1>
          <p class="hero-sub">{{ c.hero.subtitle }}</p>
          <div class="hero-actions">
            <a class="btn btn-cobalt" href="#cta">
              <span class="btn-arrow" aria-hidden="true">→</span>
              <span>{{ c.hero.docsCta }}</span>
            </a>
            <a class="btn btn-ghost" href="https://github.com" rel="noopener">
              <svg class="btn-icon" viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.05-.19-.36-.97.08-2.02 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.05.13 1.83.08 2.02.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8Z" /></svg>
              <span>{{ c.githubLabel }}</span>
            </a>
          </div>
          <p class="trust-strip">{{ c.hero.trustStrip }}</p>
        </div>
        <figure class="hero-mascot">
          <span class="state-chip">{{ c.hero.mascotLabel }}</span>
          <img src="/mascots/hero-run.jpg" width="430" height="430" :alt="c.hero.mascotAlt">
        </figure>
      </div>

      <div class="bento" aria-label="Runtime authority overview">
        <div class="bento-head">
          <span class="bento-glyph" aria-hidden="true">◉</span>
          <div>
            <strong>{{ c.bento.daemon }}</strong>
            <p class="bento-caption">{{ c.bento.daemonCaption }}</p>
          </div>
          <span class="bento-live"><i aria-hidden="true" />{{ c.bento.live }}</span>
        </div>
        <div class="bento-grid">
          <div class="bento-col">
            <p class="col-label">{{ c.bento.clientsLabel }}</p>
            <ul class="client-list">
              <li v-for="client in c.bento.clients" :key="client.name">
                <span>{{ client.name }}</span><em>{{ client.state }}</em>
              </li>
            </ul>
          </div>
          <div class="bento-col">
            <div class="col-head">
              <p class="col-title">{{ c.bento.journalLabel }}</p>
              <p class="col-label muted">{{ c.bento.journalCaption }}</p>
            </div>
            <article
              v-for="(entry, i) in c.bento.entries"
              :key="entry.id"
              class="journal-card"
              :class="[entry.tone, { selected: i === 0 }]"
            >
              <div class="journal-top">
                <span class="journal-id">{{ entry.id }}</span>
                <span class="journal-status">{{ entry.status }}</span>
              </div>
              <h3>{{ entry.title }}</h3>
              <p class="journal-detail">{{ entry.detail }}</p>
            </article>
          </div>
          <div class="bento-col">
            <div class="col-head">
              <p class="col-label">{{ c.bento.workspacesLabel }}</p>
              <span class="lock-glyph" aria-hidden="true">⚿</span>
            </div>
            <ul class="ws-list">
              <li v-for="ws in c.bento.workspaces" :key="ws" :class="{ active: ws === 'workspace/alpha' }">
                <i aria-hidden="true" />{{ ws }}
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
