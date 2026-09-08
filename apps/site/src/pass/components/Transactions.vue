<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, fmtDate, fmtNum, type Transaction } from '../api';

const props = defineProps<{ workspaceId: string }>();

const TYPES = ['', 'credit', 'debit', 'reservation', 'settlement', 'refund', 'adjustment'];
const TYPE_LABELS: Record<string, string> = {
  '': 'все типы',
  credit: 'Пополнение',
  debit: 'Списание',
  reservation: 'Резерв',
  settlement: 'Расчёт',
  refund: 'Возврат',
  adjustment: 'Корректировка',
};
const PAGE = 50;

const items = ref<Transaction[]>([]);
const total = ref(0);
const offset = ref(0);
const type = ref('');
const error = ref<string | null>(null);

async function load(nextOffset: number) {
  error.value = null;
  try {
    const q = new URLSearchParams({ limit: String(PAGE), offset: String(nextOffset) });
    if (type.value) q.set('type', type.value);
    const res = await api.get<{ transactions: Transaction[]; pagination: { total: number } }>(
      `/v1/workspaces/${props.workspaceId}/transactions?${q}`,
    );
    items.value = nextOffset === 0 ? res.transactions : [...items.value, ...res.transactions];
    total.value = res.pagination.total;
    offset.value = nextOffset;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось загрузить';
  }
}

onMounted(() => void load(0));

function onTypeChange() {
  void load(0);
}
</script>

<template>
  <div class="card">
    <h2>Транзакции</h2>
    <div class="row" style="margin-bottom: 12px">
      <select v-model="type" @change="onTypeChange">
        <option v-for="t in TYPES" :key="t" :value="t">{{ TYPE_LABELS[t] }}</option>
      </select>
      <span class="muted">всего: {{ total }}</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Дата</th>
          <th>Тип</th>
          <th class="num">Сумма</th>
          <th class="num">Баланс после</th>
          <th>Описание</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in items" :key="t.id">
          <td class="muted">{{ fmtDate(t.created_at) }}</td>
          <td><span class="badge">{{ TYPE_LABELS[t.type] ?? t.type }}</span></td>
          <td class="num" :class="Number(t.amount) >= 0 ? 'ok-text' : 'error-text'">
            {{ (Number(t.amount) >= 0 ? '+' : '') + fmtNum(t.amount) }}
          </td>
          <td class="num">{{ fmtNum(t.balance_after) }}</td>
          <td class="muted">{{ t.description }}</td>
        </tr>
        <tr v-if="items.length === 0">
          <td colspan="5" class="muted">Нет транзакций</td>
        </tr>
      </tbody>
    </table>
    <button
      v-if="offset + PAGE < total"
      class="btn btn-ghost"
      style="margin-top: 12px"
      @click="load(offset + PAGE)"
    >
      Показать ещё
    </button>
    <div v-if="error" class="error-text">{{ error }}</div>
  </div>
</template>
