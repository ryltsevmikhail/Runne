<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "../stores/auth";

const { login } = useAuth();
const router = useRouter();

const email = ref("");
const password = ref("");
const error = ref<string | null>(null);
const busy = ref(false);

async function onSubmit() {
  error.value = null;
  busy.value = true;
  try {
    await login(email.value, password.value);
    router.push("/");
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Ошибка входа";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="auth-box card">
    <span class="brand">Runne Pass</span>
    <h2>Вход в кабинет</h2>
    <form @submit.prevent="onSubmit">
      <label class="field">
        <span>Email</span>
        <input v-model="email" type="email" required autofocus />
      </label>
      <label class="field">
        <span>Пароль</span>
        <input v-model="password" type="password" required />
      </label>
      <button class="btn" style="width: 100%" :disabled="busy">
        {{ busy ? "Входим…" : "Войти" }}
      </button>
      <div v-if="error" class="error-text">{{ error }}</div>
    </form>
    <div class="auth-switch">
      Нет аккаунта? <RouterLink to="/register">Зарегистрироваться</RouterLink>
    </div>
  </div>
</template>
