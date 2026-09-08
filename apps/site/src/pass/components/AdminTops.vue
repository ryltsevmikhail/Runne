<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, fmtNum } from '../api';

interface TopWorkspace {
  workspace_id: string;
  name: string;
  customer_email: string | null;
  balance_tokens: string;
  usage_tokens_30d: string;
  requests_count_30d: number;
}

interface TopModel {
  model_id: string;
  name: string;
  provider: string;
  total_tokens_30d: string;
  total_cost_30d: string;
  requests_count_30d: number;
}

const workspaces = ref<TopWorkspace[] | null>(null);
const models = ref<TopModel[] | null>(null);
const error = ref<string | null>(null);

onMounted(async () => {
  try {
    const [w, m] = await Promise.all([
      api.get<{ workspaces: TopWorkspace[] }>('/v1/admin/dashboard/top-workspaces?limit=10'),
      api.get<{ models: TopModel[] }>('/v1/admin/dashboard/top-models?limit=10'),
    ]);
    workspaces.value = w.workspaces;
    models.value = m.models;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Ошибка загрузки';
  }
});
</script>

<template>
  <div class="grid-2">
    <div class="card">
      <h2>Топ воркспейсов</h2>
      <div v-if="workspaces === null" class="muted">Загрузка…</div>
      <table v-else>
        <thead>
          <tr>
            <th>Воркспейс</th>
            <th>Клиент</th>
            <th class="num">Баланс</th>
            <th class="num">Токены 30д</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="w in workspaces" :key="w.workspace_id">
            <td>{{ w.name }}</td>
            <td class="muted">{{ w.customer_email ?? '—' }}</td>
            <td class="num">{{ fmtNum(w.balance_tokens) }}</td>
            <td class="num">{{ fmtNum(w.usage_tokens_30d) }}</td>
          </tr>
          <tr v-if="workspaces.length === 0">
            <td colspan="4" class="muted">Нет данных</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Топ моделей</h2>
      <div v-if="models === null" class="muted">Загрузка…</div>
      <table v-else>
        <thead>
          <tr>
            <th>Модель</th>
            <th>Провайдер</th>
            <th class="num">Токены 30д</th>
            <th class="num">Расход 30д</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in models" :key="m.model_id">
            <td>{{ m.name }}</td>
            <td class="muted">{{ m.provider }}</td>
            <td class="num">{{ fmtNum(m.total_tokens_30d) }}</td>
            <td class="num">{{ fmtNum(m.total_cost_30d) }}</td>
          </tr>
          <tr v-if="models.length === 0">
            <td colspan="4" class="muted">Нет данных</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="error" class="error-text">{{ error }}</div>
  </div>
</template>
