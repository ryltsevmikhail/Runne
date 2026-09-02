export const prerenderRoutes = [
  {
    path: "/",
    lang: "en",
    output: "index.html",
    title: "The agent runtime that survives its own window",
    description:
      "Runne is an open-source Rust runtime for AI coding agents. Execution state is durable, completion requires verification evidence, and every dangerous action needs a capability grant.",
    heading: "The agent runtime that survives its own window.",
  },
  {
    path: "/ru",
    lang: "ru",
    output: "ru/index.html",
    title: "Среда выполнения агента, которая переживёт собственное окно",
    description:
      "Runne — открытая среда выполнения на Rust для AI-агентов разработки. Состояние сохраняется, завершение требует подтверждений, а каждое опасное действие — явного разрешения.",
    heading: "Среда выполнения агента, которая переживёт собственное окно.",
  },
];

export const notFoundRoute = {
  path: "/404",
  lang: "en",
  output: "404.html",
  title: "Page not found",
  description: "The requested Runne page does not exist.",
  heading: "Route not found.",
};
