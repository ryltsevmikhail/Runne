import { de } from "./dictionaries/de";
import { en } from "./dictionaries/en";
import { es } from "./dictionaries/es";
import { fr } from "./dictionaries/fr";
import { ja } from "./dictionaries/ja";
import { ko } from "./dictionaries/ko";
import { ptBr } from "./dictionaries/pt-br";
import { ru } from "./dictionaries/ru";
import { zhCn } from "./dictionaries/zh-cn";
import type { SiteDictionary } from "./page-types";
import type { Locale } from "./types";

const dictionaries: Record<Locale, SiteDictionary> = {
  en,
  ru,
  "zh-cn": zhCn,
  "pt-br": ptBr,
  es,
  de,
  ja,
  ko,
  fr,
};

export function getDictionary(locale: Locale): SiteDictionary {
  return dictionaries[locale];
}
