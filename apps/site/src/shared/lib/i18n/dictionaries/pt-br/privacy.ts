import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "Privacidade",
    description: "Informações de privacidade para a build estática do site GOCODE.",
    eyebrow: "Privacidade",
    heading: "Este site estático não coleta dados de contato.",
    lead: "O formulário está inativo: não há envio de e-mail, cadastro ou outra coleta de dados de contato.",
    panelLabel: "● sem envio de dados",
    panelTitle: "Link informativo",
    panelBody:
      "O bloco da lista de espera não cria uma inscrição nem envia informações a terceiros.",
  },
  boundary: {
    eyebrow: "Limite da página",
    heading: "Não informe dados de contato: o site não tem para onde enviá-los.",
    items: [
      {
        title: "Sem conta",
        body: "A build estática não oferece cadastro nem login.",
      },
      {
        title: "Sem formulário ativo",
        body: "A lista de espera é apenas um bloco informativo.",
      },
      {
        title: "Termos separados serão necessários mais tarde",
        body: "Futuros produtos e serviços desktop exigirão políticas publicadas explicitamente.",
      },
    ],
  },
} satisfies PrivacyPageCopy;
