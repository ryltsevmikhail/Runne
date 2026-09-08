<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, fmtDate, type ApiKey } from '../api';

const props = defineProps<{ workspaceId: string }>();

const SCOPES = ['chat:write', 'balance:read', 'models:read'];

const keys = ref<ApiKey[] | null>(null);
const name = ref('');
const selected = ref<string[]>(['chat:write']);
const rawKey = ref<string | null>(null);
const error = ref<string | null>(null);
const busy = ref(false);

async function load() {
  try {
    const res = await api.get<{ api_keys: ApiKey[] }>(`/v1/workspaces/${props.workspaceId}/api-keys`);
    keys.value = res.api_keys;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось загрузить ключи';
  }
}

onMounted(() => void load());

async function create() {
  busy.value = true;
  error.value = null;
  try {
    const res = await api.post<{ raw_key: string }>(`/v1/workspaces/${props.workspaceId}/api-keys`, {
      name: name.value.trim(),
      scopes: selected.value,
    });
    rawKey.value = res.raw_key;
    name.value = '';
    await load();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось создать ключ';
  } finally {
    busy.value = false;
  }
}

async function revoke(id: string) {
  if (!confirm('Отозвать ключ? Клиенты с ним перестанут работать.')) return;
  try {
    await api.delete(`/v1/workspaces/${props.workspaceId}/api-keys/${id}`);
    await load();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Не удалось отозвать';
  }
}

function toggleScope(id: string) {
  selected.value = selected.value.includes(id)
    ? selected.value.filter((s) => s !== id)
    : [...selected.value, id];
}
</script>

<template>
  <div class="card">
    <h2>API-ключи</h2>
    <div v-if="keys === null" class="muted">Загрузка…</div>
    <table v-else>
      <thead>
        <tr>
          <th>Название</th>
          <th>Скоупы</th>
          <th>Создан</th>
          <th>Статус</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="k in keys" :key="k.id">
          <td>{{ k.name }}</td>
          <td class="muted">{{ k.scopes.join(', ') }}</td>
          <td class="muted">{{ fmtDate(k.created_at) }}</td>
          <td>
            <span v-if="k.revoked_at" class="badge badge-bad">отозван</span>
            <span v-else class="badge badge-ok">активен</span>
          </td>
          <td>
            <button v-if="!k.revoked_at" class="btn btn-danger btn-sm" @click="revoke(k.id)">
              Отозвать
            </button>
          </td>
        </tr>
        <tr v-if="keys.length === 0">
          <td colspan="5" class="muted">Ключей пока нет</td>
        </tr>
      </tbody>
    </table>

    <div class="row" style="margin-top: 16px">
      <input
        v-model="name"
        placeholder="Название ключа, например «prod-backend»"
        style="flex: 1; min-width: 240px"
        @keyup.enter="create"
      />
      <button class="btn" :disabled="busy || !name.trim() || selected.length === 0" @click="create">
        {{ busy ? 'Создаём…' : 'Создать ключ' }}
      </button>
    </div>
    <div class="row">
      <span class="muted" style="font-size: 13px">Скоупы:</span>
      <button
        v-for="s in SCOPES"
        :key="s"
        type="button"
        class="chip"
        :class="{ active: selected.includes(s) }"
        @click="toggleScope(s)"
      >
        {{ s }}
      </button>
    </div>

    <div v-if="rawKey" class="key-reveal">
      <div class="muted" style="margin-bottom: 6px">Скопируйте ключ сейчас — он показывается только один раз:</div>
      {{ rawKey }}
    </div>
    <div v-if="error" class="error-text">{{ error }}</div>
  </div>
</template>
