import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription:
    "Локальная среда выполнения для надёжной работы с AI-агентами.",
  skipToContent: "Перейти к содержанию",
  homeAriaLabel: "GOCODE — главная",
  primaryNavAriaLabel: "Основная навигация",
  footerNavAriaLabel: "Навигация в подвале",
  languageLabel: "Язык",
  waitlistCta: "Записаться в лист ожидания",
  nav: {
    product: "Продукт",
    architecture: "Архитектура",
    security: "Безопасность",
    roadmap: "План развития",
    status: "Статус",
  },
  footer: {
    description: "Локальная среда выполнения для AI-агентов.",
    privacy: "Приватность",
    preview: "letsgocode.dev · предварительная версия",
  },
  waitlist: {
    eyebrow: "Вперёд с GOCODE",
    heading: "Присоединяйтесь к закрытой предварительной версии.",
    body: "Эта ссылка информационная: форма неактивна, контактные данные не собираются.",
    statusLink: "Читать статус разработки",
  },
  notFound: {
    title: "Страница не найдена",
    description: "Запрошенная страница GOCODE не существует.",
    eyebrow: "404",
    heading: "Маршрут не найден.",
    body: "У этой страницы нет опубликованного адреса.",
    backHome: "На главную",
  },
} satisfies SharedCopy;
