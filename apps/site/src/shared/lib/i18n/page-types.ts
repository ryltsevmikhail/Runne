import type {
  CardCopy,
  LabelledCopy,
  MockupCopy,
  PageHeroCopy,
  Quad,
  Quint,
  SectionCopy,
  Sext,
  Triple,
} from "./types";

export interface HomePageCopy {
  hero: PageHeroCopy & { cta: string; mockup: MockupCopy };
  why: SectionCopy & { items: Triple<LabelledCopy> };
  architecture: SectionCopy & { flow: Quint<LabelledCopy> };
  preview: SectionCopy & {
    verified: { label: string; title: string; items: Quad<string> };
    review: { label: string; title: string; items: Triple<string> };
  };
  roadmap: SectionCopy & { cards: Triple<CardCopy> };
}

export interface ProductPageCopy {
  hero: PageHeroCopy & { boundary: string; cta: string; mockup: MockupCopy };
  workflow: SectionCopy & { steps: Quad<LabelledCopy> };
  workspace: SectionCopy & { items: Triple<LabelledCopy> };
}

export interface ArchitecturePageCopy {
  hero: PageHeroCopy & { status: string; cards: Quad<CardCopy> };
  flow: SectionCopy & { items: Quint<LabelledCopy> };
  boundary: SectionCopy & {
    desktop: LabelledCopy & { status: string };
    runtime: LabelledCopy & { status: string };
  };
  replay: SectionCopy & { steps: Quad<LabelledCopy> };
}

export interface SecurityPageCopy {
  hero: PageHeroCopy & { panelEyebrow: string; panelBody: string };
  trust: SectionCopy & { cards: Triple<CardCopy> };
  mechanisms: SectionCopy & { cards: Sext<CardCopy> };
  boundary: SectionCopy & { items: Triple<string>; roadmapCta: string };
}

export interface RoadmapPageCopy {
  hero: PageHeroCopy & {
    panelLabel: string;
    panelTitle: string;
    panelBody: string;
    warning: string;
  };
  stages: SectionCopy & { cards: Triple<CardCopy> };
  exclusions: SectionCopy & { items: Triple<LabelledCopy> };
  legend: SectionCopy & { cards: Triple<CardCopy> };
}

export interface StatusPageCopy {
  hero: PageHeroCopy & {
    panelLabel: string;
    panelTitle: string;
    panelBody: string;
    platform: string;
  };
  snapshot: SectionCopy & { cards: Quad<CardCopy> };
  boundaries: SectionCopy & {
    current: { label: string; title: string; items: Quad<string> };
    open: { label: string; title: string; items: Quad<string> };
  };
  platforms: SectionCopy & {
    items: Triple<{ name: string; status: string }>;
  };
}

export interface PrivacyPageCopy {
  hero: PageHeroCopy & {
    panelLabel: string;
    panelTitle: string;
    panelBody: string;
  };
  boundary: SectionCopy & { items: Triple<LabelledCopy> };
}

export interface PageCopies {
  home: HomePageCopy;
  product: ProductPageCopy;
  architecture: ArchitecturePageCopy;
  security: SecurityPageCopy;
  roadmap: RoadmapPageCopy;
  status: StatusPageCopy;
  privacy: PrivacyPageCopy;
}

export type PageCopy<K extends keyof PageCopies> = PageCopies[K];

export type SiteDictionary = {
  shared: import("./types").SharedCopy;
  pages: PageCopies;
};
