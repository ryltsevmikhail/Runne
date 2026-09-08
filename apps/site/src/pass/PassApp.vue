<script setup lang="ts">
import { onMounted, watchEffect } from "vue";
import { RouterView, useRoute, useRouter } from "vue-router";
import { useAuth } from "./stores/auth";
import PassHeader from "./PassHeader.vue";

const { user, loading, logout, refresh } = useAuth();
const route = useRoute();
const router = useRouter();

onMounted(() => {
  void refresh();
});

watchEffect(() => {
  if (loading.value) return;
  const publicPage = route.path === "/login" || route.path === "/register";
  if (!user.value && !publicPage) router.replace("/login");
  if (user.value && publicPage) router.replace("/");
  if (route.path.startsWith("/admin") && !user.value?.is_platform_admin) {
    router.replace("/");
  }
});

function onLogout() {
  logout();
  router.push("/login");
}
</script>

<template>
  <div class="pass-app">
    <PassHeader :email="user?.email" :is-admin="user?.is_platform_admin ?? false" @logout="onLogout" />
    <div v-if="loading" class="page muted">Загрузка…</div>
    <RouterView v-else />
  </div>
</template>
