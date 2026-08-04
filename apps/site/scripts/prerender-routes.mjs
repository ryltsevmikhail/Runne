export const prerenderRoutes = [
  {
    path: "/",
    output: "index.html",
    title: "AI coding agents — under your control",
    description:
      "GOCODE is a desktop control center for AI agents, backed by a local runtime with verifiable boundaries.",
    heading: "AI coding agents — under your control.",
  },
  {
    path: "/product",
    output: "product/index.html",
    title: "Product",
    description:
      "GOCODE brings the local project, conversation, and runtime state together in one desktop app.",
    heading: "One control center for working with AI agents.",
  },
  {
    path: "/architecture",
    output: "architecture/index.html",
    title: "Architecture",
    description:
      "The GOCODE runtime owns state, while the interface controls it only through a verifiable public contract.",
    heading: "The runtime owns state. The interface owns control.",
  },
  {
    path: "/security",
    output: "security/index.html",
    title: "Security",
    description:
      "Uncertain state receives no permission to act: GOCODE security boundaries are verifiable.",
    heading: "Uncertain state receives no permission to act.",
  },
  {
    path: "/roadmap",
    output: "roadmap/index.html",
    title: "Roadmap",
    description:
      "The GOCODE roadmap puts evidence before release, without unverified availability promises.",
    heading: "Evidence first. Release second.",
  },
  {
    path: "/status",
    output: "status/index.html",
    title: "Development status",
    description:
      "Verified GOCODE implementation evidence and exact boundaries of the current preview.",
    heading: "What works now. What is still ahead.",
  },
  {
    path: "/privacy",
    output: "privacy/index.html",
    title: "Privacy",
    description: "Privacy information for the static GOCODE site build.",
    heading: "This static site does not collect contact data.",
  },
];

export const notFoundRoute = {
  path: "/404",
  output: "404.html",
  title: "Page not found",
  description: "The requested GOCODE page does not exist.",
  heading: "Route not found.",
};
