<script setup lang="ts">
import { ref } from 'vue';
import { api } from '../api';

const props = defineProps<{ workspaceId: string }>();

const PRESETS = ['1000', '5000', '10000'];

const amount = ref('5000');
const error = ref<string | null>(null);
const busy = ref(false);

async function onSubmit() {
  error.value = null;
  busy.value = true;
  try {
    const res = await api.post<{ confirmation_url: string }>('/v1/payments', {
      workspace_id: props.workspaceId,
      amount_rubles: Number(amount.value).toFixed(2),
      description: `Пополнение баланса Runne Pass (${amount.value} ₽)`,
    });
    window.location.href = res.confirmation_url;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось создать платёж';
    busy.value = false;
  }
}
</script>

<template>
  <div class="card">
    <h2>Пополнить баланс</h2>
    <div class="muted" style="margin-bottom: 10px">
      1 токен = 1 ₽. Оплата картой или через СБП на защищённой странице платёжного
      провайдера. Минимальная сумма — 100 ₽.
    </div>
    <form @submit.prevent="onSubmit">
      <div class="row">
        <button
          v-for="p in PRESETS"
          :key="p"
          type="button"
          class="tab"
          :class="{ active: amount === p }"
          @click="amount = p"
        >
          {{ Number(p).toLocaleString('ru-RU') }} ₽
        </button>
        <input v-model="amount" type="number" min="100" step="1" style="width: 140px" required />
        <button class="btn" :disabled="busy || Number(amount) < 100">
          {{ busy ? 'Переходим к оплате…' : 'Пополнить' }}
        </button>
      </div>
      <div v-if="error" class="error-text">{{ error }}</div>
    </form>
  </div>
</template>
