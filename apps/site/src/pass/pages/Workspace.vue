<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { api, fmtNum, type Workspace } from "../api";
import ApiKeys from "../components/ApiKeys.vue";
import Transactions from "../components/Transactions.vue";
import UsageReport from "../components/UsageReport.vue";
import TopUp from "../components/TopUp.vue";

const TABS = [
  { id: "keys", label: "API-ключи" },
  { id: "topup", label: "Пополнение" },
  { id: "transactions", label: "Транзакции" },
  { id: "usage", label: "Расходы" },
] as const;
type TabId = (typeof TABS)[number]["id"];

const route = useRoute();
const workspaceId = computed(() => String(route.params.workspaceId));

const ws = ref<Workspace | null>(null);
const quotaUsed = ref<string | null>(null);
const error = ref<string | null>(null);
const tab = ref<TabId>("keys");

async function load() {
  try {
    const list = await api.get<{ workspaces: Workspace[] }>("/v1/workspaces");
    ws.value = list.workspaces.find((w) => w.id === workspaceId.value) ?? null;
    if (!ws.value) error.value = "Воркспейс не найден";
    try {
      const u = await api.get<{ usage?: { tokens_used?: string }; tokens_used?: string }>(
        `/v1/workspaces/${workspaceId.value}/quota/usage`,
      );
      quotaUsed.value = u.usage?.tokens_used ?? u.tokens_used ?? null;
    } catch {
      quotaUsed.value = null;
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Ошибка загрузки";
  }
}

onMounted(() => void load());
</script>

<template>
  <div class="page">
    <div v-if="error">
      <div class="error-text">{{ error }}</div>
      <RouterLink to="/" class="muted">← в кабинет</RouterLink>
    </div>

    <template v-else-if="ws">
      <RouterLink to="/" class="muted">← все воркспейсы</RouterLink>
      <h1 style="margin-top: 10px">{{ ws.name }}</h1>

      <div class="cards">
        <div class="stat">
          <div class="label">Баланс</div>
          <div class="value">{{ fmtNum(ws.balance) }} ₽</div>
        </div>
        <div class="stat">
          <div class="label">Использовано за период</div>
          <div class="value">{{ quotaUsed !== null ? fmtNum(quotaUsed) : "—" }}</div>
        </div>
        <div class="stat">
          <div class="label">Статус</div>
          <div class="value">
            <span class="badge" :class="ws.status === 'active' ? 'badge-ok' : 'badge-bad'">
              {{ ws.status }}
            </span>
          </div>
        </div>
      </div>

      <div class="tabs">
        <button
          v-for="t in TABS"
          :key="t.id"
          class="tab"
          :class="{ active: tab === t.id }"
          @click="tab = t.id"
        >
          {{ t.label }}
        </button>
      </div>

      <ApiKeys v-if="tab === 'keys'" :workspace-id="ws.id" />
      <TopUp v-if="tab === 'topup'" :workspace-id="ws.id" />
      <Transactions v-if="tab === 'transactions'" :workspace-id="ws.id" />
      <UsageReport v-if="tab === 'usage'" :workspace-id="ws.id" />
    </template>

    <div v-else class="muted">Загрузка…</div>
  </div>
</template>
