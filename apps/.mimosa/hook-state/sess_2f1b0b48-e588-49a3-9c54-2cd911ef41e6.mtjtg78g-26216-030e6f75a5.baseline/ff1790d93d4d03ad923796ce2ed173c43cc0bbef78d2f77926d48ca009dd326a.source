import { inject } from "vue";
import { ContentKey, LangKey, type Lang, type SiteContent } from "./content";

export function useSite(): { lang: Lang; c: SiteContent } {
  const lang = inject(LangKey, "en");
  const c = inject(ContentKey)!;
  return { lang, c };
}

export function langPath(to: Lang): string {
  return to === "ru" ? "/ru" : "/";
}
