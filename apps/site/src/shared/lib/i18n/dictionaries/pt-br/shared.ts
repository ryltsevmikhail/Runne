import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "Um runtime local para trabalhar com AI de forma confiável.",
  skipToContent: "Ir para o conteúdo",
  homeAriaLabel: "Página inicial do GOCODE",
  primaryNavAriaLabel: "Navegação principal",
  footerNavAriaLabel: "Navegação do rodapé",
  languageLabel: "Idioma",
  waitlistCta: "Entrar na lista de espera",
  nav: {
    product: "Produto",
    architecture: "Arquitetura",
    security: "Segurança",
    roadmap: "Roteiro",
    status: "Status",
  },
  footer: {
    description: "Um runtime local para agentes de AI.",
    privacy: "Privacidade",
    preview: "letsgocode.dev · prévia",
  },
  waitlist: {
    eyebrow: "Avance com o GOCODE",
    heading: "Participe da prévia privada.",
    body: "Este link é informativo: o formulário está inativo e nenhum dado de contato é coletado.",
    statusLink: "Ver status do desenvolvimento",
  },
  notFound: {
    title: "Página não encontrada",
    description: "A página solicitada do GOCODE não existe.",
    eyebrow: "404",
    heading: "Rota não encontrada.",
    body: "Esta página não possui um endereço publicado.",
    backHome: "Voltar ao início",
  },
} satisfies SharedCopy;
