<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, fmtNum, type Workspace } from "../api";

const workspaces = ref<Workspace[] | null>(null);
const name = ref("");
const error = ref<string | null>(null);
const busy = ref(false);

const active = computed(() => (workspaces.value ?? []).filter((w) => w.status === "active"));
const archived = computed(() => (workspaces.value ?? []).filter((w) => w.status !== "active"));

async function load() {
  try {
    const res = await api.get<{ workspaces: Workspace[] }>("/v1/workspaces");
    workspaces.value = res.workspaces;
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Не удалось загрузить";
    workspaces.value = [];
  }
}

onMounted(() => void load());

async function createWorkspace() {
  if (!name.value.trim()) return;
  busy.value = true;
  error.value = null;
  try {
    await api.post("/v1/workspaces", { name: name.value.trim() });
    name.value = "";
    await load();
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Не удалось создать";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="page">
    <h1>Личный кабинет</h1>

    <div class="card">
      <h2>Мои воркспейсы</h2>
      <div v-if="workspaces === null" class="muted">Загрузка…</div>
      <div v-else-if="active.length === 0" class="muted">
        Пока нет ни одного воркспейса — создайте первый ниже.
      </div>
      <div class="cards">
        <RouterLink v-for="w in active" :key="w.id" :to="`/workspaces/${w.id}`" class="ws-card">
          <div>{{ w.name }}</div>
          <div class="balance">{{ fmtNum(w.balance) }} <span class="muted">токенов</span></div>
          <div class="muted" style="font-size: 13px">1 токен = 1 ₽</div>
        </RouterLink>
      </div>
      <div class="row">
        <input
          v-model="name"
          placeholder="Название нового воркспейса"
          style="min-width: 280px"
          @keyup.enter="createWorkspace"
        />
        <button class="btn" :disabled="busy || !name.trim()" @click="createWorkspace">
          {{ busy ? "Создаём…" : "Создать воркспейс" }}
        </button>
      </div>
      <div v-if="error" class="error-text">{{ error }}</div>
    </div>

    <div v-if="archived.length > 0" class="card">
      <h2>Архив / заблокированные</h2>
      <table>
        <thead>
          <tr>
            <th>Название</th>
            <th>Статус</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="w in archived" :key="w.id">
            <td>{{ w.name }}</td>
            <td><span class="badge badge-bad">{{ w.status }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
