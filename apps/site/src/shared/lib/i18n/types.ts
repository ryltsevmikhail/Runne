export const localeCodes = [
  "en",
  "ru",
  "zh-cn",
  "pt-br",
  "es",
  "de",
  "ja",
  "ko",
  "fr",
] as const;

export type Locale = (typeof localeCodes)[number];
export type TranslationLocale = Exclude<Locale, "en" | "ru">;

export const pageKeys = [
  "home",
  "product",
  "architecture",
  "security",
  "roadmap",
  "status",
  "privacy",
] as const;

export type PageKey = (typeof pageKeys)[number];
export type NavPageKey = Exclude<PageKey, "home" | "privacy">;

export type Pair<T> = readonly [T, T];
export type Triple<T> = readonly [T, T, T];
export type Quad<T> = readonly [T, T, T, T];
export type Quint<T> = readonly [T, T, T, T, T];
export type Sext<T> = readonly [T, T, T, T, T, T];

export interface PageHeroCopy {
  title: string;
  description: string;
  eyebrow: string;
  heading: string;
  lead: string;
}

export interface SectionCopy {
  eyebrow: string;
  heading: string;
  lead?: string;
}

export interface LabelledCopy {
  title: string;
  body: string;
}

export interface CardCopy extends LabelledCopy {
  label?: string;
}

export interface MockupCopy {
  ariaLabel: string;
  topLabel: string;
  status: string;
  railTitle: string;
  project: string;
  railItems: Pair<string>;
  chatTitle: string;
  state: string;
  message: string;
  input: string;
}

export interface SharedCopy {
  siteDescription: string;
  skipToContent: string;
  homeAriaLabel: string;
  primaryNavAriaLabel: string;
  footerNavAriaLabel: string;
  languageLabel: string;
  waitlistCta: string;
  nav: Record<NavPageKey, string>;
  footer: {
    description: string;
    privacy: string;
    preview: string;
  };
  waitlist: {
    eyebrow: string;
    heading: string;
    body: string;
    statusLink: string;
  };
  notFound: {
    title: string;
    description: string;
    eyebrow: string;
    heading: string;
    body: string;
    backHome: string;
  };
}
