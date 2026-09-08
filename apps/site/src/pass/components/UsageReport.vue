<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, fmtNum } from '../api';

const props = defineProps<{ workspaceId: string }>();

interface Report {
  total_cost: string;
  total_requests: number;
  total_tokens: string;
  breakdown: { period: string; cost: string; requests: number; tokens: string }[];
}

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

const from = ref(isoDay(new Date(Date.now() - 30 * 86400_000)));
const to = ref(isoDay(new Date()));
const groupBy = ref('day');
const report = ref<Report | null>(null);
const error = ref<string | null>(null);
const busy = ref(false);

async function load() {
  busy.value = true;
  error.value = null;
  try {
    const q = new URLSearchParams({ from: `${from.value}T00:00:00Z`, to: `${to.value}T23:59:59Z`, group_by: groupBy.value });
    report.value = await api.get<Report>(`/v1/workspaces/${props.workspaceId}/usage-report?${q}`);
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось загрузить отчёт';
  } finally {
    busy.value = false;
  }
}

onMounted(() => void load());
</script>

<template>
  <div class="card">
    <h2>Отчёт по расходам</h2>
    <div class="row" style="margin-bottom: 14px">
      <span class="muted">с</span>
      <input v-model="from" type="date" />
      <span class="muted">по</span>
      <input v-model="to" type="date" />
      <select v-model="groupBy">
        <option value="day">по дням</option>
        <option value="week">по неделям</option>
        <option value="month">по месяцам</option>
        <option value="model">по моделям</option>
      </select>
      <button class="btn" :disabled="busy" @click="load">
        {{ busy ? 'Считаем…' : 'Обновить' }}
      </button>
    </div>

    <div v-if="report" class="cards">
      <div class="stat">
        <div class="label">Расход, токенов</div>
        <div class="value">{{ fmtNum(report.total_cost) }}</div>
      </div>
      <div class="stat">
        <div class="label">Токенов обработано</div>
        <div class="value">{{ fmtNum(report.total_tokens) }}</div>
      </div>
      <div class="stat">
        <div class="label">Запросов</div>
        <div class="value">{{ fmtNum(report.total_requests) }}</div>
      </div>
    </div>

    <table v-if="report && report.breakdown.length > 0">
      <thead>
        <tr>
          <th>{{ groupBy === 'model' ? 'Модель' : 'Период' }}</th>
          <th class="num">Токены</th>
          <th class="num">Запросы</th>
          <th class="num">Расход, ₽</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="b in report.breakdown" :key="b.period">
          <td>{{ b.period }}</td>
          <td class="num">{{ fmtNum(b.tokens) }}</td>
          <td class="num">{{ fmtNum(b.requests) }}</td>
          <td class="num">{{ fmtNum(b.cost) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-if="report && report.breakdown.length === 0" class="muted">
      За выбранный период расходов нет.
    </div>
    <div v-if="error" class="error-text">{{ error }}</div>
  </div>
</template>
