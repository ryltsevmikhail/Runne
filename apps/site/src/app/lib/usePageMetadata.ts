import { watchEffect, type Ref } from "vue";
import type { RouteLocationNormalizedLoaded } from "vue-router";
import { site } from "../../shared/config/site";
import type { SiteDictionary } from "../../shared/lib/i18n/page-types";
import { localeMetadata } from "../../shared/lib/i18n/locales";
import type { Locale } from "../../shared/lib/i18n/types";
import { useSiteI18n } from "../../shared/lib/i18n/useSiteI18n";
import { routePageKey } from "../router";

function setMeta(selector: string, attribute: "content" | "href", value: string) {
  document.querySelector<HTMLElement>(selector)?.setAttribute(attribute, value);
}

function updateRobots(notFound: boolean) {
  const current = document.querySelector<HTMLMetaElement>('meta[data-runtime="robots"]');
  if (!notFound) {
    current?.remove();
    return;
  }
  const meta = current ?? document.createElement("meta");
  meta.name = "robots";
  meta.content = "noindex, nofollow";
  meta.dataset.runtime = "robots";
  if (!current) document.head.append(meta);
}

export interface PageMetadata {
  canonical: string;
  description: string;
  htmlLang: string;
  notFound: boolean;
  ogLocale: string;
  title: string;
}

export function resolvePageMetadata(
  routeName: unknown,
  routePath: string,
  dictionary: SiteDictionary,
  locale: Locale,
): PageMetadata {
  const notFound = routeName === "not-found";
  const copy = notFound
    ? dictionary.shared.notFound
    : dictionary.pages[routePageKey(routeName)].hero;
  return {
    canonical: new URL(routePath, site.url).toString(),
    description: copy.description,
    htmlLang: localeMetadata[locale].htmlLang,
    notFound,
    ogLocale: localeMetadata[locale].ogLocale,
    title: `${copy.title} · ${site.name}`,
  };
}

export function usePageMetadata(route: Ref<RouteLocationNormalizedLoaded>) {
  const { dictionary, locale } = useSiteI18n();

  watchEffect(() => {
    if (typeof document === "undefined") return;
    const metadata = resolvePageMetadata(
      route.value.name,
      route.value.path,
      dictionary.value,
      locale.value,
    );

    document.documentElement.lang = metadata.htmlLang;
    document.title = metadata.title;
    setMeta('meta[name="description"]', "content", metadata.description);
    setMeta('link[rel="canonical"]', "href", metadata.canonical);
    setMeta('meta[property="og:title"]', "content", metadata.title);
    setMeta('meta[property="og:description"]', "content", metadata.description);
    setMeta('meta[property="og:url"]', "content", metadata.canonical);
    setMeta('meta[property="og:locale"]', "content", metadata.ogLocale);
    setMeta('meta[name="twitter:title"]', "content", metadata.title);
    setMeta('meta[name="twitter:description"]', "content", metadata.description);
    updateRobots(metadata.notFound);
  });
}
