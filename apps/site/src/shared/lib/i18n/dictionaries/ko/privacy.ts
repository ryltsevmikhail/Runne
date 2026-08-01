import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "개인정보 보호",
    description: "정적 GOCODE 사이트 빌드의 개인정보 보호 정보입니다.",
    eyebrow: "개인정보 보호",
    heading: "이 정적 사이트는 연락처 데이터를 수집하지 않습니다.",
    lead: "양식은 비활성 상태입니다. 이메일 제출, 등록 또는 그 밖의 연락처 데이터 수집이 없습니다.",
    panelLabel: "● 데이터 제출 없음",
    panelTitle: "정보 링크",
    panelBody:
      "대기자 명단 블록은 신청을 만들거나 제3자에게 정보를 보내지 않습니다.",
  },
  boundary: {
    eyebrow: "페이지 경계",
    heading: "연락처 데이터를 입력하지 마세요. 사이트에는 보낼 곳이 없습니다.",
    items: [
      {
        title: "계정 없음",
        body: "정적 빌드는 등록이나 로그인을 제공하지 않습니다.",
      },
      { title: "활성 양식 없음", body: "대기자 명단은 정보 블록일 뿐입니다." },
      {
        title: "향후 별도 약관 필요",
        body: "향후 데스크톱 제품과 서비스에는 명시적으로 게시된 정책이 필요합니다.",
      },
    ],
  },
} satisfies PrivacyPageCopy;
