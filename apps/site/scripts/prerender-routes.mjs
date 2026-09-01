export const prerenderRoutes = [
  {
    path: "/",
    output: "index.html",
    title: "The agent runtime that survives its own window",
    description:
      "Runne is an open-source Rust runtime for AI coding agents. Execution state is durable, completion requires verification evidence, and every dangerous action needs a capability grant.",
    heading: "The agent runtime that survives its own window.",
  },
];

export const notFoundRoute = {
  path: "/404",
  output: "404.html",
  title: "Page not found",
  description: "The requested Runne page does not exist.",
  heading: "Route not found.",
};
