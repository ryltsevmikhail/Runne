<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, fmtNum } from "../api";
import AdminTops from "../components/AdminTops.vue";

interface Overview {
  totalCustomers: number;
  activeCustomers: number;
  totalWorkspaces: number;
  totalBalanceTokens: string;
  totalUsageTokens30d: string;
  totalRevenue30d: string;
  activeApiKeys: number;
}

interface Customer {
  customer_id: string;
  email: string;
  name: string;
  status: string;
  created_at: string;
  workspaces_count: number;
}

const TABS = [
  { id: "overview", label: "Обзор" },
  { id: "customers", label: "Клиенты" },
  { id: "tops", label: "Топы" },
] as const;
type TabId = (typeof TABS)[number]["id"];

const tab = ref<TabId>("overview");

const overview = ref<Overview | null>(null);
const overviewError = ref<string | null>(null);

const statCards = computed(() => {
  if (!overview.value) return [];
  const o = overview.value;
  return [
    { label: "Клиентов", value: fmtNum(o.totalCustomers) },
    { label: "Активных клиентов", value: fmtNum(o.activeCustomers) },
    { label: "Воркспейсов", value: fmtNum(o.totalWorkspaces) },
    { label: "Суммарный баланс, ₽", value: fmtNum(o.totalBalanceTokens) },
    { label: "Доход 30д, ₽", value: fmtNum(o.totalRevenue30d) },
    { label: "Токенов за 30д", value: fmtNum(o.totalUsageTokens30d) },
    { label: "Активных API-ключей", value: fmtNum(o.activeApiKeys) },
  ];
});

onMounted(async () => {
  try {
    const r = await api.get<{ overview: Overview }>("/v1/admin/dashboard/overview");
    overview.value = r.overview;
  } catch (err) {
    overviewError.value = err instanceof Error ? err.message : "Ошибка загрузки";
  }
});

const customers = ref<Customer[]>([]);
const page = ref(1);
const total = ref(0);
const statusFilter = ref("");
const customersError = ref<string | null>(null);
const limit = 20;
const pages = computed(() => Math.max(1, Math.ceil(total.value / limit)));

async function loadCustomers() {
  customersError.value = null;
  try {
    const q = new URLSearchParams({ page: String(page.value), limit: String(limit) });
    if (statusFilter.value) q.set("status", statusFilter.value);
    const res = await api.get<{ customers: Customer[]; pagination: { total: number } }>(
      `/v1/admin/customers?${q}`,
    );
    customers.value = res.customers;
    total.value = res.pagination.total;
  } catch (err) {
    customersError.value = err instanceof Error ? err.message : "Ошибка загрузки";
  }
}

onMounted(() => void loadCustomers());

async function setStatusOf(customerId: string, next: "active" | "suspended") {
  const verb = next === "suspended" ? "Заблокировать" : "Разблокировать";
  if (!confirm(`${verb} клиента? Его API-ключи будут отозваны.`)) return;
  try {
    await api.put(`/v1/admin/customers/${customerId}/status`, { status: next });
    await loadCustomers();
  } catch (err) {
    customersError.value = err instanceof Error ? err.message : "Не удалось изменить статус";
  }
}

function goToPage(p: number) {
  page.value = p;
  void loadCustomers();
}
</script>

<template>
  <div class="page">
    <h1>Админка</h1>
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

    <div v-if="tab === 'overview'">
      <div v-if="!overview && !overviewError" class="muted">Загрузка…</div>
      <div v-if="overview" class="cards">
        <div v-for="c in statCards" :key="c.label" class="stat">
          <div class="label">{{ c.label }}</div>
          <div class="value">{{ c.value }}</div>
        </div>
      </div>
      <div v-if="overviewError" class="error-text">{{ overviewError }}</div>
    </div>

    <div v-if="tab === 'customers'" class="card">
      <div class="row" style="margin-bottom: 12px">
        <select v-model="statusFilter" @change="page = 1; loadCustomers()">
          <option value="">все статусы</option>
          <option value="active">active</option>
          <option value="suspended">suspended</option>
        </select>
        <span class="muted">всего: {{ total }}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th>Имя</th>
            <th>Статус</th>
            <th class="num">Воркспейсы</th>
            <th>Создан</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in customers" :key="c.customer_id">
            <td>
              <RouterLink
                :to="`/admin/customers/${c.customer_id}`"
                style="color: var(--accent)"
              >
                {{ c.email }}
              </RouterLink>
            </td>
            <td>{{ c.name }}</td>
            <td>
              <span class="badge" :class="c.status === 'active' ? 'badge-ok' : 'badge-bad'">
                {{ c.status }}
              </span>
            </td>
            <td class="num">{{ c.workspaces_count }}</td>
            <td class="muted">{{ new Date(c.created_at).toLocaleDateString("ru-RU") }}</td>
            <td>
              <button
                v-if="c.status === 'active'"
                class="btn btn-danger btn-sm"
                @click="setStatusOf(c.customer_id, 'suspended')"
              >
                Блок
              </button>
              <button
                v-else
                class="btn btn-ghost btn-sm"
                @click="setStatusOf(c.customer_id, 'active')"
              >
                Разблок
              </button>
            </td>
          </tr>
          <tr v-if="customers.length === 0">
            <td colspan="6" class="muted">Нет клиентов</td>
          </tr>
        </tbody>
      </table>
      <div v-if="pages > 1" class="row" style="margin-top: 12px">
        <button class="btn btn-ghost btn-sm" :disabled="page <= 1" @click="goToPage(page - 1)">
          ← назад
        </button>
        <span class="muted">стр. {{ page }} из {{ pages }}</span>
        <button class="btn btn-ghost btn-sm" :disabled="page >= pages" @click="goToPage(page + 1)">
          вперёд →
        </button>
      </div>
      <div v-if="customersError" class="error-text">{{ customersError }}</div>
    </div>

    <AdminTops v-if="tab === 'tops'" />
  </div>
</template>
