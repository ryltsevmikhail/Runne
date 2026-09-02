import type { InjectionKey } from "vue";

export type Lang = "en" | "ru";

export const site = {
  name: "Runne",
  url: "https://runne.run",
} as const;

export const LangKey: InjectionKey<Lang> = Symbol("lang");
export const ContentKey: InjectionKey<SiteContent> = Symbol("content");

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
  hero: {
    headline: string;
    subtitle: string;
    trustStrip: string;
    mascotLabel: string;
    mascotAlt: string;
    docsCta: string;
  };
  bento: {
    daemon: string;
    daemonCaption: string;
    live: string;
    clientsLabel: string;
    clients: Client[];
    journalLabel: string;
    journalCaption: string;
    entries: JournalEntry[];
    workspacesLabel: string;
    workspaces: string[];
  };
  comic: {
    eyebrow: string;
    headline: string;
    intro: string;
    chips: string[];
    panels: Panel[];
    closing: { headline: string; detail: string };
    guarantees: {
      eyebrow: string;
      headline: string;
      items: { n: string; name: string; body: string }[];
    };
    chapter2: {
      eyebrow: string;
      headline: string;
      intro: string;
      panels: WidePanel[];
      budget: {
        header: string;
        rows: { label: string; value: string; pct: number }[];
        limit: string;
      };
    };
  };
  demo: {
    eyebrow: string;
    headline: string;
    body: string;
    chip: string;
    task: string;
    active: string;
    steps: { n: string; label: string; done: boolean; active: boolean }[];
    runState: { heading: string; metrics: { label: string; value: string }[] };
    command: string;
  };
  contract: {
    eyebrow: string;
    headline: string;
    body: string;
    notes: string[];
    nodes: { title: string; caption: string; tone: "light" | "dark" }[];
  };
  cta: { headline: string; body: string; docs: string; github: string };
  footer: {
    proposition: string;
    columns: { heading: string; links: string[] }[];
    copyright: string;
    status: string;
  };
}

const en: SiteContent = {
  navLinks: [
    { label: "Architecture", href: "#architecture" },
    { label: "Capabilities", href: "#capabilities" },
    { label: "Philosophy", href: "#philosophy" },
    { label: "Status", href: "#status" },
  ],
  docsLabel: "Read the docs",
  githubLabel: "View on GitHub",
  langSwitch: { to: "ru", label: "Русский" },
  hero: {
    headline: "The agent runtime that survives its own window.",
    subtitle:
      "Runne is a local-first Rust runtime for AI coding agents. Execution state is durable, completion requires verification evidence, and every dangerous action needs a capability grant. The chat window is a view. The runtime is the truth.",
    trustStrip:
      "Rust · 40 crates · ~3,400 tests · 25 documented subsystems · one local process · no telemetry",
    mascotLabel: "TaskRun · active",
    mascotAlt: "Runne mascot running with an active TaskRun",
    docsCta: "Read the docs",
  },
  bento: {
    daemon: "runned daemon (Rust)",
    daemonCaption: "RUNTIME AUTHORITY · CONFIRMED PROJECTIONS ONLY",
    live: "runned · live",
    clientsLabel: "CLIENTS",
    clients: [
      { name: "Desktop", state: "connected" },
      { name: "CLI", state: "connected" },
      { name: "API", state: "connected" },
    ],
    journalLabel: "Event Journal",
    journalCaption: "ORDERED · DURABLE · REPLAYABLE",
    entries: [
      {
        id: "TR-0184",
        status: "Completed · evidence attached",
        tone: "ok",
        title: "Acceptance verification",
        detail: "cursor 184 · acknowledged",
      },
      {
        id: "TR-0185",
        status: "RecoveryBlocked",
        tone: "blocked",
        title: "Workspace mutation",
        detail: "cursor 185 · explicit state",
      },
    ],
    workspacesLabel: "ISOLATED WORKSPACES",
    workspaces: ["workspace/alpha", "workspace/beta", "workspace/gamma"],
  },
  comic: {
    eyebrow: "RUNNE FIELD NOTES · ISSUE 001",
    headline: "A coding task walks into a runtime.",
    intro:
      "Follow Runne through the moment a request becomes durable, controlled, and provably complete.",
    chips: ["6 PANELS", "1 SOURCE OF TRUTH"],
    panels: [
      {
        n: "01",
        kicker: "THE REQUEST",
        speech: "Got it. First, I make it durable.",
        title: "A task arrives.",
        body: "Runne turns the prompt into a TaskRun with an identity, a timeline, and a budget.",
        image: "/mascots/panel-01.jpg",
      },
      {
        n: "02",
        kicker: "THE INTERRUPTION",
        speech: "Window gone? I’m still here.",
        title: "The window disappears.",
        body: "The UI can close. The provider can stall. The authoritative run keeps its place.",
        image: "/mascots/panel-02.jpg",
      },
      {
        n: "03",
        kicker: "THE RECOVERY",
        speech: "Found the last safe step.",
        title: "Nothing is lost.",
        body: "Runne replays the journal and resumes from confirmed state—not from a hopeful guess.",
        image: "/mascots/panel-03.jpg",
      },
      {
        n: "04",
        kicker: "THE BOUNDARY",
        speech: "Show me the grant first.",
        title: "Tools ask permission.",
        body: "Files, shells, networks, and secrets stay behind explicit capability grants.",
        image: "/mascots/panel-04.jpg",
      },
      {
        n: "05",
        kicker: "THE PROOF",
        speech: "Nice claim. Where’s the proof?",
        title: "“Done” is challenged.",
        body: "Tests, checks, and artifacts become verification evidence attached to the run.",
        image: "/mascots/panel-05.jpg",
      },
      {
        n: "06",
        kicker: "THE OUTCOME",
        speech: "Verified. Recorded. Done.",
        title: "Now it can ship.",
        body: "You get a completed task with chronology, evidence, and an audit trail clients can trust.",
        image: "/mascots/panel-06.jpg",
      },
    ],
    closing: {
      headline: "The chat is a view. Runne is the continuity.",
      detail: "Durable execution · capability security · verification evidence",
    },
    guarantees: {
      eyebrow: "THE THREE GUARANTEES",
      headline: "Not a character trait. A runtime contract.",
      items: [
        { n: "01", name: "DURABLE", body: "The run survives its window." },
        { n: "02", name: "CONTROLLED", body: "Every dangerous action needs a grant." },
        { n: "03", name: "VERIFIED", body: "Completion carries evidence." },
      ],
    },
    chapter2: {
      eyebrow: "THE STORY GETS BIGGER · ISSUE 002",
      headline: "One run becomes a whole operating system.",
      intro:
        "The same runtime boundary keeps working as clients, providers, budgets, and histories multiply.",
      panels: [
        {
          n: "07",
          kicker: "MANY CLIENTS",
          runtimeLabel: "ONE RUNTIME",
          speech: "Different windows. Same run.",
          title: "Everyone sees the same truth.",
          body: "Desktop, CLI, and API clients read confirmed runtime projections instead of inventing their own state.",
        },
        {
          n: "09",
          kicker: "BOUNDED WORK",
          speech: "That’s the limit. We stop here.",
          title: "The budget has a guardian.",
          body: "Token, time, and tool limits are enforced while accounting remains visible and attributable.",
        },
      ],
      budget: {
        header: "RUN BUDGET",
        rows: [
          { label: "TOKENS", value: "78%", pct: 78 },
          { label: "TIME", value: "42%", pct: 42 },
          { label: "TOOLS", value: "3 / 5", pct: 60 },
        ],
        limit: "LIMIT ACTIVE",
      },
    },
  },
  demo: {
    eyebrow: "LIVE RUNTIME",
    headline: "See the run. Not just the chat.",
    body:
      "Every step is backed by the journal: state, permissions, budget, and verification evidence live in one place.",
    chip: "TR-0184 · RUNNING",
    task: "TASKRUN / TR-0184",
    active: "ACTIVE",
    steps: [
      { n: "01", label: "Request accepted", done: true, active: false },
      { n: "02", label: "Workspace prepared", done: true, active: false },
      { n: "03", label: "Agent working", done: true, active: true },
      { n: "04", label: "Verification queued", done: false, active: false },
    ],
    runState: {
      heading: "RUN STATE",
      metrics: [
        { label: "Capability grants", value: "3 / 3" },
        { label: "Budget used", value: "78%" },
        { label: "Journal cursor", value: "184" },
      ],
    },
    command: "runne task inspect TR-0184",
  },
  contract: {
    eyebrow: "UNDER THE PANELS",
    headline: "The simple shape behind every Runne story.",
    body:
      "Clients request work. The runtime decides what is allowed, records what actually happened, and publishes only confirmed state.",
    notes: ["LOCAL-FIRST", "PROVIDER-NEUTRAL", "CONTRACT-DRIVEN"],
    nodes: [
      { title: "Clients", caption: "DESKTOP · CLI · API", tone: "light" },
      { title: "runned", caption: "AUTHORITATIVE RUST RUNTIME", tone: "dark" },
      { title: "Event journal", caption: "SQLITE · ORDERED · REPLAYABLE", tone: "light" },
    ],
  },
  cta: {
    headline: "Read the contracts. Run the runtime.",
    body: "Runne is local-first and designed to be inspected.",
    docs: "Read the docs",
    github: "View on GitHub →",
  },
  footer: {
    proposition: "A proof-carrying runtime for AI coding agents.",
    columns: [
      { heading: "PRODUCT", links: ["Runtime", "Desktop", "CLI"] },
      { heading: "RESOURCES", links: ["Documentation", "Architecture", "GitHub"] },
      { heading: "PROJECT", links: ["Principles", "Security", "Roadmap"] },
    ],
    copyright: "© 2026 Runne",
    status: "RUNTIME STATUS · OPERATIONAL",
  },
};

const ru: SiteContent = {
  navLinks: [
    { label: "Архитектура", href: "#architecture" },
    { label: "Возможности", href: "#capabilities" },
    { label: "Принципы", href: "#philosophy" },
    { label: "Статус", href: "#status" },
  ],
  docsLabel: "Документация",
  githubLabel: "Открыть GitHub",
  langSwitch: { to: "en", label: "English" },
  hero: {
    headline: "Среда выполнения агента, которая переживёт собственное окно.",
    subtitle:
      "Runne — локальная среда выполнения на Rust для AI-агентов разработки. Состояние выполнения сохраняется, завершение требует подтверждений, а каждое опасное действие — явного разрешения. Окно чата — лишь представление. Истина находится в runtime.",
    trustStrip:
      "Rust · 40 крейтов · ~3 400 тестов · 25 документированных подсистем · один локальный процесс · без телеметрии",
    mascotLabel: "TaskRun · активен",
    mascotAlt: "Талисман Runne бежит с активным TaskRun",
    docsCta: "Документация",
  },
  bento: {
    daemon: "runned daemon (Rust)",
    daemonCaption: "RUNTIME — ИСТОЧНИК ИСТИНЫ · ТОЛЬКО ПОДТВЕРЖДЁННЫЕ ПРОЕКЦИИ",
    live: "runned · live",
    clientsLabel: "КЛИЕНТЫ",
    clients: [
      { name: "Приложение", state: "подключён" },
      { name: "CLI", state: "подключён" },
      { name: "API", state: "подключён" },
    ],
    journalLabel: "Журнал событий",
    journalCaption: "УПОРЯДОЧЕН · НАДЁЖЕН · ВОСПРОИЗВОДИМ",
    entries: [
      {
        id: "TR-0184",
        status: "Завершено · подтверждения приложены",
        tone: "ok",
        title: "Приёмочная проверка",
        detail: "курсор 184 · подтверждён",
      },
      {
        id: "TR-0185",
        status: "Восстановление заблокировано",
        tone: "blocked",
        title: "Изменение рабочей области",
        detail: "курсор 185 · явное состояние",
      },
    ],
    workspacesLabel: "ИЗОЛИРОВАННЫЕ РАБОЧИЕ ОБЛАСТИ",
    workspaces: ["workspace/alpha", "workspace/beta", "workspace/gamma"],
  },
  comic: {
    eyebrow: "ПОЛЕВЫЕ ЗАПИСКИ RUNNE · ВЫПУСК 001",
    headline: "Задача разработки попадает в runtime.",
    intro:
      "Проследите вместе с Runne, как запрос становится надёжным, контролируемым и доказуемо завершённым.",
    chips: ["6 ПАНЕЛЕЙ", "1 ИСТОЧНИК ИСТИНЫ"],
    panels: [
      {
        n: "01",
        kicker: "ЗАПРОС",
        speech: "Принято. Сначала всё сохраним.",
        title: "Задача поступила.",
        body: "Runne превращает запрос в TaskRun с идентификатором, хронологией и бюджетом.",
        image: "/mascots/panel-01.jpg",
      },
      {
        n: "02",
        kicker: "СБОЙ",
        speech: "Окно исчезло? Я всё ещё здесь.",
        title: "Окно исчезает.",
        body: "Интерфейс может закрыться, провайдер — зависнуть. Авторитетный запуск сохранит своё состояние.",
        image: "/mascots/panel-02.jpg",
      },
      {
        n: "03",
        kicker: "ВОССТАНОВЛЕНИЕ",
        speech: "Нашёл последний безопасный шаг.",
        title: "Ничего не потеряно.",
        body: "Runne воспроизводит журнал и продолжает с подтверждённого состояния, а не с догадки.",
        image: "/mascots/panel-03.jpg",
      },
      {
        n: "04",
        kicker: "ГРАНИЦА",
        speech: "Сначала покажи разрешение.",
        title: "Инструменты запрашивают доступ.",
        body: "Файлы, терминал, сеть и секреты доступны только по явным capability-разрешениям.",
        image: "/mascots/panel-04.jpg",
      },
      {
        n: "05",
        kicker: "ДОКАЗАТЕЛЬСТВО",
        speech: "Хорошо звучит. А где доказательства?",
        title: "Слово «готово» проверяется.",
        body: "Тесты, проверки и артефакты становятся доказательствами, приложенными к запуску.",
        image: "/mascots/panel-05.jpg",
      },
      {
        n: "06",
        kicker: "РЕЗУЛЬТАТ",
        speech: "Проверено. Записано. Готово.",
        title: "Теперь можно выпускать.",
        body: "Вы получаете завершённую задачу с хронологией, доказательствами и надёжным аудитом.",
        image: "/mascots/panel-06.jpg",
      },
    ],
    closing: {
      headline: "Чат — это представление. Runne — непрерывность.",
      detail: "Надёжное выполнение · контроль доступа · доказательства проверки",
    },
    guarantees: {
      eyebrow: "ТРИ ГАРАНТИИ",
      headline: "Не черта характера. Контракт среды выполнения.",
      items: [
        { n: "01", name: "НАДЁЖНОСТЬ", body: "Запуск переживёт своё окно." },
        { n: "02", name: "КОНТРОЛЬ", body: "Каждому опасному действию нужно разрешение." },
        { n: "03", name: "ПРОВЕРКА", body: "Завершение подкреплено доказательствами." },
      ],
    },
    chapter2: {
      eyebrow: "ИСТОРИЯ СТАНОВИТСЯ БОЛЬШЕ · ВЫПУСК 002",
      headline: "Один запуск превращается в целую операционную систему.",
      intro:
        "Единая граница runtime продолжает работать, когда клиентов, провайдеров, бюджетов и историй становится больше.",
      panels: [
        {
          n: "07",
          kicker: "МНОГО КЛИЕНТОВ",
          runtimeLabel: "ОДИН RUNTIME",
          speech: "Разные окна. Один запуск.",
          title: "Все видят одну истину.",
          body: "Desktop, CLI и API читают подтверждённые проекции runtime, а не придумывают собственное состояние.",
        },
        {
          n: "09",
          kicker: "ОГРАНИЧЕННАЯ РАБОТА",
          speech: "Это лимит. Здесь остановимся.",
          title: "У бюджета есть хранитель.",
          body: "Лимиты токенов, времени и инструментов видимы и соблюдаются.",
        },
      ],
      budget: {
        header: "БЮДЖЕТ ЗАПУСКА",
        rows: [
          { label: "ТОКЕНЫ", value: "78%", pct: 78 },
          { label: "ВРЕМЯ", value: "42%", pct: 42 },
          { label: "ИНСТРУМ.", value: "3 / 5", pct: 60 },
        ],
        limit: "ЛИМИТ АКТИВЕН",
      },
    },
  },
  demo: {
    eyebrow: "ЖИВОЙ RUNTIME",
    headline: "Видно запуск, а не только чат.",
    body:
      "Каждый шаг подтверждён журналом: состояние, разрешения, бюджет и доказательства находятся в одном месте.",
    chip: "TR-0184 · ВЫПОЛНЯЕТСЯ",
    task: "TASKRUN / TR-0184",
    active: "АКТИВЕН",
    steps: [
      { n: "01", label: "Запрос принят", done: true, active: false },
      { n: "02", label: "Рабочая область готова", done: true, active: false },
      { n: "03", label: "Агент выполняет задачу", done: true, active: true },
      { n: "04", label: "Проверка ожидает", done: false, active: false },
    ],
    runState: {
      heading: "СОСТОЯНИЕ ЗАПУСКА",
      metrics: [
        { label: "Разрешения", value: "3 / 3" },
        { label: "Бюджет", value: "78%" },
        { label: "Курсор журнала", value: "184" },
      ],
    },
    command: "runne task inspect TR-0184",
  },
  contract: {
    eyebrow: "ЗА КАДРАМИ",
    headline: "Простая схема в основе каждой истории Runne.",
    body:
      "Клиенты запрашивают работу. Runtime определяет допустимое, записывает произошедшее и публикует только подтверждённое состояние.",
    notes: ["LOCAL-FIRST", "PROVIDER-NEUTRAL", "CONTRACT-DRIVEN"],
    nodes: [
      { title: "Клиенты", caption: "DESKTOP · CLI · API", tone: "light" },
      { title: "runned", caption: "АВТОРИТЕТНЫЙ RUNTIME НА RUST", tone: "dark" },
      { title: "Журнал событий", caption: "SQLITE · УПОРЯДОЧЕН · ВОСПРОИЗВОДИМ", tone: "light" },
    ],
  },
  cta: {
    headline: "Изучите контракты. Запустите runtime.",
    body: "Runne работает локально и создан для прозрачности.",
    docs: "Документация",
    github: "Открыть GitHub →",
  },
  footer: {
    proposition: "Среда выполнения AI-агентов с доказательствами.",
    columns: [
      { heading: "ПРОДУКТ", links: ["Среда выполнения", "Приложение", "CLI"] },
      { heading: "РЕСУРСЫ", links: ["Документация", "Архитектура", "GitHub"] },
      { heading: "ПРОЕКТ", links: ["Принципы", "Безопасность", "План развития"] },
    ],
    copyright: "© 2026 Runne",
    status: "СТАТУС RUNTIME · РАБОТАЕТ",
  },
};

export const contents: Record<Lang, SiteContent> = { en, ru };

export const langOf = (url: string): Lang => (url === "/ru" || url.startsWith("/ru/") ? "ru" : "en");
