import { ref } from 'vue';
import { api, clearToken, getToken, setToken, type Me } from '../api';

const user = ref<Me | null>(null);
const loading = ref(true);

async function refresh(): Promise<void> {
  if (!getToken()) {
    user.value = null;
    loading.value = false;
    return;
  }
  try {
    user.value = await api.get<Me>('/v1/auth/me');
  } catch {
    clearToken();
    user.value = null;
  } finally {
    loading.value = false;
  }
}

async function login(email: string, password: string): Promise<void> {
  const res = await api.post<{ sessionToken: string }>('/v1/auth/login', { email, password });
  setToken(res.sessionToken);
  await refresh();
}

async function register(email: string, name: string, password: string): Promise<void> {
  await api.post('/v1/auth/register', { email, name, password });
  await login(email, password);
}

function logout(): void {
  clearToken();
  user.value = null;
}

export function useAuth() {
  return { user, loading, refresh, login, register, logout };
}
