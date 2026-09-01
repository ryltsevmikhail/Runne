import { renderToString } from "@vue/server-renderer";
import { createSSRApp } from "vue";
import App from "./App.vue";

const SITE_NAME = "Runne";
const SITE_URL = "https://runne.run";

const pageMeta: Record<string, { title: string; description: string; notFound: boolean }> = {
  "/": {
    title: "The agent runtime that survives its own window",
    description:
      "Runne is an open-source Rust runtime for AI coding agents. Execution state is durable, completion requires verification evidence, and every dangerous action needs a capability grant.",
    notFound: false,
  },
  "/404": {
    title: "Page not found",
    description: "The requested Runne page does not exist.",
    notFound: true,
  },
};

export async function render(url: string) {
  const meta = pageMeta[url] ?? pageMeta["/404"];
  const app = createSSRApp(App, { notFound: meta.notFound });
  return {
    appHtml: await renderToString(app),
    metadata: {
      htmlLang: "en",
      title: `${meta.title} · ${SITE_NAME}`,
      description: meta.description,
      canonical: `${SITE_URL}${url}`,
      ogLocale: "en_US",
      notFound: meta.notFound,
    },
  };
}
