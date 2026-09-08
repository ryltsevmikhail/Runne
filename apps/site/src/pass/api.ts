const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? 'https://api-production-973e.up.railway.app';

const TOKEN_KEY = 'runne_session_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const res = await fetch(`${BASE}${path}`, { ...init, headers });

  if (res.status === 204) return undefined as T;

  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const message =
      body?.error?.message ?? body?.error ?? body?.message ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, String(message));
  }
  return body as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, data?: unknown) =>
    request<T>(path, { method: 'POST', body: data ? JSON.stringify(data) : undefined }),
  put: <T>(path: string, data: unknown) =>
    request<T>(path, { method: 'PUT', body: JSON.stringify(data) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};

// ---------- DTO ----------

export interface Me {
  customer_id: string;
  email: string;
  name: string;
  status: string;
  is_platform_admin: boolean;
}

export interface Workspace {
  id: string;
  name: string;
  balance: string;
  currency: string;
  status: string;
  created_at?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  scopes: string[];
  key_id?: string;
  revoked_at: string | null;
  created_at?: string;
  last_used_at?: string | null;
}

export interface Transaction {
  id: string;
  type: string;
  amount: string;
  description: string;
  balance_after: string;
  created_at: string;
}

export interface Payment {
  payment_id: string;
  amount_rubles: string;
  tokens_credited: string;
  status: string;
  created_at?: string;
}

export function fmtDate(v?: string | null): string {
  if (!v) return '—';
  return new Date(v).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
}

export function fmtNum(v: string | number): string {
  return Number(v).toLocaleString('ru-RU');
}
