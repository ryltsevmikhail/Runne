<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, fmtDate, fmtNum } from '../api';

const props = defineProps<{ workspaceId: string }>();

const open = ref(false);
const payments = ref<PaymentRow[] | null>(null);
const quota = ref<Quota | null>(null);
const error = ref<string | null>(null);
const okText = ref<string | null>(null);
const busy = ref(false);

interface PaymentRow {
  payment_id: string;
  provider: string;
  amount_rubles: string;
  tokens_credited: string;
  status: string;
  created_at: string;
}

interface Quota {
  tokens_per_month: string | null;
  requests_per_minute: string | null;
  max_api_keys_per_workspace: string | null;
}

const adjustAmount = ref('');
const adjustDescription = ref('');
const quotaForm = ref({ tokens_per_month: '', requests_per_minute: '', max_api_keys_per_workspace: '' });

async function loadPayments() {
  try {
    const res = await api.get<{ payments: PaymentRow[] }>(
      `/v1/admin/workspaces/${props.workspaceId}/payments`,
    );
    payments.value = res.payments;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Ошибка загрузки платежей';
  }
}

async function loadQuota() {
  try {
    const res = await api.get<{ quota: Quota | null }>(`/v1/workspaces/${props.workspaceId}/quota`);
    quota.value = res.quota;
    quotaForm.value = {
      tokens_per_month: res.quota?.tokens_per_month ?? '',
      requests_per_minute: res.quota?.requests_per_minute ?? '',
      max_api_keys_per_workspace: res.quota?.max_api_keys_per_workspace ?? '',
    };
  } catch {
    quota.value = null;
  }
}

function toggle() {
  open.value = !open.value;
  if (open.value) {
    if (payments.value === null) void loadPayments();
    if (quota.value === null) void loadQuota();
  }
}

async function adjust(direction: 1 | -1) {
  error.value = null;
  okText.value = null;
  const raw = adjustAmount.value.trim();
  if (!raw) return;
  busy.value = true;
  try {
    const signed = direction === 1 ? raw : `-${raw}`;
    const res = await api.post<{ new_balance: string }>(
      `/v1/admin/workspaces/${props.workspaceId}/adjust`,
      { amount: signed, description: adjustDescription.value.trim() || `Ручная корректировка (${direction === 1 ? '+' : '-'}${raw})` },
    );
    okText.value = `Готово. Новый баланс: ${fmtNum(res.new_balance)} ₽`;
    adjustAmount.value = '';
    adjustDescription.value = '';
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось применить';
  } finally {
    busy.value = false;
  }
}

async function saveQuota() {
  error.value = null;
  okText.value = null;
  busy.value = true;
  try {
    const body: Record<string, string> = {};
    for (const [k, v] of Object.entries(quotaForm.value)) {
      if (v !== '') body[k] = v;
    }
    await api.put(`/v1/admin/workspaces/${props.workspaceId}/quota`, body);
    okText.value = 'Квота обновлена';
    await loadQuota();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось сохранить квоту';
  } finally {
    busy.value = false;
  }
}

onMounted(() => {
  void loadQuota();
});
</script>

<template>
  <div class="card">
    <div class="row" style="justify-content: space-between; cursor: pointer" @click="toggle">
      <h2 style="margin: 0">Управление</h2>
      <span class="muted">{{ open ? 'свернуть ▲' : 'открыть ▼' }}</span>
    </div>
    <slot />

    <template v-if="open">
      <h3 style="margin: 16px 0 8px">Корректировка баланса</h3>
      <div class="row">
        <input v-model="adjustAmount" type="number" min="0" step="0.01" placeholder="Сумма, ₽" style="width: 140px" />
        <input v-model="adjustDescription" placeholder="Описание (в аудит-лог)" style="min-width: 260px" />
        <button class="btn" :disabled="busy || !adjustAmount" @click="adjust(1)">Начислить</button>
        <button class="btn btn-danger" :disabled="busy || !adjustAmount" @click="adjust(-1)">Списать</button>
      </div>

      <h3 style="margin: 16px 0 8px">Квоты (пусто = без лимита)</h3>
      <div class="row">
        <input v-model="quotaForm.tokens_per_month" placeholder="tokens/мес" style="width: 140px" />
        <input v-model="quotaForm.requests_per_minute" placeholder="req/мин" style="width: 120px" />
        <input v-model="quotaForm.max_api_keys_per_workspace" placeholder="макс ключей" style="width: 130px" />
        <button class="btn btn-ghost" :disabled="busy" @click="saveQuota">Сохранить квоту</button>
      </div>

      <h3 style="margin: 16px 0 8px">
        Платежи
        <button class="btn btn-ghost btn-sm" style="margin-left: 10px" @click="loadPayments">Обновить</button>
      </h3>
      <table v-if="payments && payments.length > 0">
        <thead>
          <tr>
            <th>Дата</th>
            <th>Провайдер</th>
            <th class="num">Сумма</th>
            <th class="num">Токены</th>
            <th>Статус</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in payments" :key="p.payment_id">
            <td class="muted">{{ fmtDate(p.created_at) }}</td>
            <td>{{ p.provider }}</td>
            <td class="num">{{ fmtNum(p.amount_rubles) }} ₽</td>
            <td class="num">{{ fmtNum(p.tokens_credited) }}</td>
            <td><span class="badge" :class="p.status === 'succeeded' ? 'badge-ok' : 'badge-warn'">{{ p.status }}</span></td>
          </tr>
        </tbody>
      </table>
      <div v-else-if="payments" class="muted">Платежей нет</div>

      <div v-if="error" class="error-text">{{ error }}</div>
      <div v-if="okText" class="ok-text">{{ okText }}</div>
    </template>
  </div>
</template>
