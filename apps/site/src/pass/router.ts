import { createRouter, createWebHashHistory } from "vue-router";
import Dashboard from "./pages/Dashboard.vue";

// Кабинет живёт внутри /pass/ (отдельный entry), хэш-роутинг не требует
// изменений в конфиге Cloudflare assets.
export const passRouter = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/login", component: () => import("./pages/Login.vue") },
    { path: "/register", component: () => import("./pages/Register.vue") },
    { path: "/", component: Dashboard },
    { path: "/workspaces/:workspaceId", component: () => import("./pages/Workspace.vue") },
    { path: "/payments/success", component: () => import("./pages/PaymentSuccess.vue") },
    { path: "/admin", component: () => import("./pages/Admin.vue") },
    {
      path: "/admin/customers/:customerId",
      component: () => import("./pages/CustomerDetail.vue"),
    },
    { path: "/:pathMatch(.*)*", redirect: "/" },
  ],
});
