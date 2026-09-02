import { renderToString } from "@vue/server-renderer";
import { createSSRApp } from "vue";
import App from "./App.vue";
import { langOf, type Lang } from "./content";

const SITE_NAME = "Runne";
const SITE_URL = "https://runne.run";

type Route = { title: string; description: string; notFound: boolean; lang: Lang; ogLocale: string };

const pageMeta: Record<string, Route> = {
  "/": {
    title: "The agent runtime that survives its own window",
    description:
      "Runne is a local-first Rust runtime for AI coding agents. Execution state is durable, completion requires verification evidence, and every dangerous action needs a capability grant.",
    notFound: false,
    lang: "en",
    ogLocale: "en_US",
  },
  "/ru": {
    title: "Среда выполнения агента, которая переживёт собственное окно",
    description:
      "Runne — локальная среда выполнения на Rust для AI-агентов разработки. Состояние сохраняется, завершение требует подтверждений, а каждое опасное действие — явного разрешения.",
    notFound: false,
    lang: "ru",
    ogLocale: "ru_RU",
  },
  "/404": {
    title: "Page not found",
    description: "The requested Runne page does not exist.",
    notFound: true,
    lang: "en",
    ogLocale: "en_US",
  },
};

export async function render(url: string) {
  const key = url === "/ru/" ? "/ru" : url;
  const meta: Route = pageMeta[key] ?? pageMeta["/404"];
  const lang = meta.notFound ? "en" : (langOf(url) as Lang);
  const app = createSSRApp(App, { path: meta.notFound ? "/" : url, notFound: meta.notFound });
  return {
    appHtml: await renderToString(app),
    metadata: {
      htmlLang: lang,
      title: `${meta.title} · ${SITE_NAME}`,
      description: meta.description,
      canonical: `${SITE_URL}${key === "/" ? "/" : key}`,
      ogLocale: meta.ogLocale,
      notFound: meta.notFound,
    },
  };
}
