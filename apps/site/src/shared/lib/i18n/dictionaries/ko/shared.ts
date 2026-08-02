import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "AI 에이전트와 안정적으로 작업하기 위한 로컬 runtime입니다.",
  skipToContent: "콘텐츠로 건너뛰기",
  homeAriaLabel: "GOCODE 홈",
  primaryNavAriaLabel: "기본 탐색",
  footerNavAriaLabel: "푸터 탐색",
  languageLabel: "언어",
  waitlistCta: "대기자 명단 참여",
  nav: {
    product: "제품",
    architecture: "아키텍처",
    security: "보안",
    roadmap: "로드맵",
    status: "상태",
  },
  footer: {
    description: "AI 에이전트를 위한 로컬 runtime입니다.",
    privacy: "개인정보 보호",
    preview: "letsgocode.dev · 미리보기",
  },
  waitlist: {
    eyebrow: "GOCODE와 함께 나아가기",
    heading: "비공개 미리보기에 참여하세요.",
    body: "이 링크는 정보 제공용입니다. 양식은 비활성 상태이며 연락처 데이터를 수집하지 않습니다.",
    statusLink: "개발 상태 보기",
  },
  notFound: {
    title: "페이지를 찾을 수 없습니다",
    description: "요청한 GOCODE 페이지가 존재하지 않습니다.",
    eyebrow: "404",
    heading: "경로를 찾을 수 없습니다.",
    body: "이 페이지에는 공개된 주소가 없습니다.",
    backHome: "홈으로 돌아가기",
  },
} satisfies SharedCopy;
