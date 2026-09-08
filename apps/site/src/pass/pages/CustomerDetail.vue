<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api, fmtDate, fmtNum } from "../api";
import { useAuth } from "../stores/auth";
import WorkspaceAdmin from "../components/WorkspaceAdmin.vue";

interface CustomerDetail {
  customer_id: string;
  email: string;
  name: string;
  status: string;
  is_platform_admin: boolean;
  created_at: string;
}

interface AdminWorkspace {
  workspace_id: string;
  name: string;
  balance: string;
  currency: string;
  status: string;
}

const route = useRoute();
const router = useRouter();
const { user } = useAuth();

const customerId = computed(() => String(route.params.customerId));

const customer = ref<CustomerDetail | null>(null);
const workspaces = ref<AdminWorkspace[]>([]);
const error = ref<string | null>(null);

async function load() {
  error.value = null;
  try {
    const res = await api.get<{ customer: CustomerDetail; workspaces: AdminWorkspace[] }>(
      `/v1/admin/customers/${customerId.value}`,
    );
    customer.value = res.customer;
    workspaces.value = res.workspaces;
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Ошибка загрузки";
  }
}

onMounted(() => {
  if (!user.value?.is_platform_admin) {
    router.replace("/");
    return;
  }
  void load();
});

async function setStatus(next: "active" | "suspended") {
  const verb = next === "suspended" ? "Заблокировать" : "Разблокировать";
  if (!confirm(`${verb} клиента ${customer.value?.email}?`)) return;
  try {
    await api.put(`/v1/admin/customers/${customerId.value}/status`, { status: next });
    await load();
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Не удалось изменить статус";
  }
}
</script>

<template>
  <div class="page">
    <RouterLink to="/admin" class="muted">← все клиенты</RouterLink>

    <div v-if="error" class="error-text">{{ error }}</div>

    <template v-else-if="customer">
      <h1 style="margin-top: 10px">{{ customer.name }}</h1>

      <div class="card">
        <div class="row" style="justify-content: space-between">
          <div>
            <div class="mono">{{ customer.email }}</div>
            <div class="muted" style="font-size: 13px">
              зарегистрирован {{ fmtDate(customer.created_at) }}
              <span v-if="customer.is_platform_admin"> · платформенный админ</span>
            </div>
          </div>
          <div class="row">
            <span class="badge" :class="customer.status === 'active' ? 'badge-ok' : 'badge-bad'">
              {{ customer.status }}
            </span>
            <button
              v-if="customer.status === 'active'"
              class="btn btn-danger btn-sm"
              @click="setStatus('suspended')"
            >
              Заблокировать
            </button>
            <button v-else class="btn btn-ghost btn-sm" @click="setStatus('active')">
              Разблокировать
            </button>
          </div>
        </div>
      </div>

      <h2>Воркспейсы ({{ workspaces.length }})</h2>
      <div v-if="workspaces.length === 0" class="muted">Воркспейсов нет</div>
      <div v-for="w in workspaces" :key="w.workspace_id" style="margin-bottom: 16px">
        <WorkspaceAdmin :workspace-id="w.workspace_id">
          <div class="row" style="margin-top: 10px">
            <strong>{{ w.name }}</strong>
            <span class="badge" :class="w.status === 'active' ? 'badge-ok' : 'badge-bad'">{{ w.status }}</span>
            <span class="mono">{{ fmtNum(w.balance) }} ₽</span>
          </div>
        </WorkspaceAdmin>
      </div>
    </template>

    <div v-else class="muted">Загрузка…</div>
  </div>
</template>
