import { createRouter, type RouterHistory, type RouteRecordRaw } from "vue-router";
import type { PageKey } from "../shared/lib/i18n/types";

export const routes = [
  {
    path: "/",
    name: "home",
    component: () => import("../pages/home/ui/HomePage.vue"),
  },
  {
    path: "/product",
    name: "product",
    component: () => import("../pages/product/ui/ProductPage.vue"),
  },
  {
    path: "/architecture",
    name: "architecture",
    component: () => import("../pages/architecture/ui/ArchitecturePage.vue"),
  },
  {
    path: "/security",
    name: "security",
    component: () => import("../pages/security/ui/SecurityPage.vue"),
  },
  {
    path: "/roadmap",
    name: "roadmap",
    component: () => import("../pages/roadmap/ui/RoadmapPage.vue"),
  },
  {
    path: "/status",
    name: "status",
    component: () => import("../pages/status/ui/StatusPage.vue"),
  },
  {
    path: "/privacy",
    name: "privacy",
    component: () => import("../pages/privacy/ui/PrivacyPage.vue"),
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("../pages/not-found/ui/NotFoundPage.vue"),
  },
] satisfies RouteRecordRaw[];

export function routePageKey(name: unknown): PageKey {
  return name === "product" ||
    name === "architecture" ||
    name === "security" ||
    name === "roadmap" ||
    name === "status" ||
    name === "privacy"
    ? name
    : "home";
}

export function createSiteRouter(history: RouterHistory) {
  return createRouter({
    history,
    routes,
    scrollBehavior(to) {
      return to.hash ? { el: to.hash, behavior: "smooth" } : { top: 0 };
    },
  });
}
