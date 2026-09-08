<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "../stores/auth";

const { register } = useAuth();
const router = useRouter();

const email = ref("");
const name = ref("");
const password = ref("");
const error = ref<string | null>(null);
const busy = ref(false);

async function onSubmit() {
  error.value = null;
  busy.value = true;
  try {
    await register(email.value, name.value, password.value);
    router.push("/");
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Ошибка регистрации";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="auth-box card">
    <span class="brand">Runne Pass</span>
    <h2>Регистрация</h2>
    <form @submit.prevent="onSubmit">
      <label class="field">
        <span>Имя или компания</span>
        <input v-model="name" required autofocus />
      </label>
      <label class="field">
        <span>Email</span>
        <input v-model="email" type="email" required />
      </label>
      <label class="field">
        <span>Пароль (минимум 8 символов)</span>
        <input v-model="password" type="password" minlength="8" required />
      </label>
      <button class="btn" style="width: 100%" :disabled="busy">
        {{ busy ? "Создаём аккаунт…" : "Создать аккаунт" }}
      </button>
      <div v-if="error" class="error-text">{{ error }}</div>
    </form>
    <div class="auth-switch">
      Уже есть аккаунт? <RouterLink to="/login">Войти</RouterLink>
    </div>
  </div>
</template>
