import type { InjectionKey } from "vue";
import { en } from "./content-en";
import { ru } from "./content-ru";

export type Lang = "en" | "ru";

export const site = {
  name: "Runne",
  url: "https://runne.run",
} as const;

export type NavLink = { label: string; href: string };
export type Client = { name: string; state: string };
export type JournalEntry = { id: string; status: string; tone: "ok" | "blocked"; title: string; detail: string };
export type Panel = { n: string; kicker: string; speech: string; title: string; body: string; image: string };
export type WidePanel = { n: string; kicker: string; runtimeLabel?: string; speech: string; title: string; body: string };

export interface SiteContent {
  navLinks: NavLink[];
  docsLabel: string;
  githubLabel: string;
  langSwitch: { to: Lang; label: string };
  hero: { headline: string; subtitle: string; trustStrip: string; mascotLabel: string; mascotAlt: string; docsCta: string };
  bento: { daemon: string; daemonCaption: string; live: string; clientsLabel: string; clients: Client[]; journalLabel: string; journalCaption: string; entries: JournalEntry[]; workspacesLabel: string; workspaces: string[] };
  comic: {
    eyebrow: string;
    headline: string;
    intro: string;
    chips: string[];
    panels: Panel[];
    closing: { headline: string; detail: string };
    guarantees: { eyebrow: string; headline: string; items: { n: string; name: string; body: string }[] };
    chapter2: { eyebrow: string; headline: string; intro: string; panels: WidePanel[]; budget: { header: string; rows: { label: string; value: string; pct: number }[]; limit: string } };
  };
  demo: { eyebrow: string; headline: string; body: string; chip: string; task: string; active: string; steps: { n: string; label: string; done: boolean; active: boolean }[]; runState: { heading: string; metrics: { label: string; value: string }[] }; command: string };
  contract: { eyebrow: string; headline: string; body: string; notes: string[]; nodes: { title: string; caption: string; tone: "light" | "dark" }[] };
  cta: { headline: string; body: string; docs: string; github: string };
  footer: { proposition: string; columns: { heading: string; links: string[] }[]; copyright: string; status: string };
}

export const LangKey: InjectionKey<Lang> = Symbol("lang");
export const ContentKey: InjectionKey<SiteContent> = Symbol("content");
export const contents: Record<Lang, SiteContent> = { en, ru };
export const langOf = (url: string): Lang => (url === "/ru" || url.startsWith("/ru/") ? "ru" : "en");
