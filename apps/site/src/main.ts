import { createApp, createSSRApp } from "vue";
import { createWebHistory } from "vue-router";
import App from "./app/App.vue";
import { createSiteRouter } from "./app/router";
import "./app/styles/global.css";
import { initializeBrowserLocale } from "./shared/lib/i18n/useSiteI18n";

const container = document.querySelector("#app");
const app = container?.firstElementChild ? createSSRApp(App) : createApp(App);
const router = createSiteRouter(createWebHistory());
app.use(router);
await router.isReady();
app.mount("#app");
initializeBrowserLocale();
