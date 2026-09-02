<script setup lang="ts">
import { useSite } from "../useSite";
const { lang } = useSite();
const label = lang === "ru" ? "На главную" : "Back to the landing";
const title = lang === "ru" ? "Страница не найдена." : "Route not found.";
const lead = lang === "ru"
  ? "Эта страница не входит в контракт runtime."
  : "This page is not part of the runtime contract.";
</script>

<template>
  <section class="not-found">
    <div class="wrap">
      <p class="eyebrow cobalt">404</p>
      <h1>{{ title }}</h1>
      <p class="lead">
        {{ lead }}
        <a href="/">{{ label }}</a>.
      </p>
    </div>
  </section>
</template>
