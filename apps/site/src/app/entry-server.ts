import { renderToString } from "@vue/server-renderer";
import { createSSRApp } from "vue";
import { createMemoryHistory } from "vue-router";
import { getDictionary } from "../shared/lib/i18n";
import App from "./App.vue";
import { resolvePageMetadata } from "./lib/usePageMetadata";
import { createSiteRouter } from "./router";

export async function render(url: string) {
  const app = createSSRApp(App);
  const router = createSiteRouter(createMemoryHistory());
  app.use(router);
  await router.push(url);
  await router.isReady();
  const route = router.currentRoute.value;

  return {
    appHtml: await renderToString(app),
    metadata: resolvePageMetadata(route.name, route.path, getDictionary("en"), "en"),
  };
}
