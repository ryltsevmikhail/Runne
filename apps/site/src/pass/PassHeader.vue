<script setup lang="ts">
import { RouterLink } from "vue-router";

defineProps<{ email?: string; isAdmin: boolean }>();
defineEmits<{ logout: [] }>();
</script>

<template>
  <header class="header">
    <a href="/pass/" class="brand">Runne Pass</a>
    <span class="muted mono brand-sub">/ MANAGED API</span>
    <nav class="nav">
      <RouterLink to="/">Кабинет</RouterLink>
      <RouterLink v-if="isAdmin" to="/admin">Админка</RouterLink>
    </nav>
    <div class="header-right">
      <span class="muted mono">{{ email }}</span>
      <button class="btn btn-ghost" @click="$emit('logout')">Выйти</button>
    </div>
  </header>
</template>
