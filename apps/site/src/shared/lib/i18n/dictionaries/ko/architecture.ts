import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "아키텍처",
    description:
      "GOCODE runtime이 상태를 소유하고 인터페이스는 검증 가능한 공개 계약을 통해서만 이를 제어합니다.",
    eyebrow: "아키텍처",
    heading: "runtime이 상태를 소유하고, 인터페이스가 제어합니다.",
    lead: "GOCODE는 권위 있는 상태, 공개 계약, 표현 계층을 분리합니다. 데스크톱 앱은 runtime client를 우회하거나 구현 내부를 import하지 않습니다.",
    status: "● 단일 신뢰 정보원",
    cards: [
      { title: "Vue / Tauri", body: "제어" },
      { title: "runtime-client", body: "공개 계약" },
      { title: "GOCODE runtime", body: "권위 있는 상태" },
      { title: "SQLite 이벤트 저널", body: "영속 기록" },
    ],
  },
  flow: {
    eyebrow: "데이터 흐름",
    heading: "명령은 하나의 검증 가능한 경계를 통과합니다.",
    lead: "HTTP, 스토리지 또는 인터페이스 상태를 통한 우회 경로는 없습니다.",
    items: [
      { title: "명령", body: "CLI / 데스크톱 앱" },
      { title: "runtime-client", body: "인증" },
      { title: "RuntimeHandle", body: "허용 및 실행" },
      { title: "이벤트 저널", body: "이벤트 커밋" },
      { title: "투영", body: "정제된 DTO" },
    ],
  },
  boundary: {
    eyebrow: "책임 경계",
    heading: "인터페이스는 투영을 읽고 runtime이 결정합니다.",
    lead: "자격 증명과 엔드포인트는 Tauri host에 남습니다. Vue는 시크릿이나 raw runtime 오류가 없는 타입 지정 DTO를 받습니다.",
    desktop: {
      title: "데스크톱 앱",
      body: "사용자 의도 · 표현 · 재시도",
      status: "상태를 소유하지 않음",
    },
    runtime: {
      title: "GOCODE runtime",
      body: "이벤트 · cursor · 투영 · 복구",
      status: "권위 있는 상태",
    },
  },
  replay: {
    eyebrow: "재생 및 계속",
    heading: "계속은 확인된 위치에서 시작합니다.",
    lead: "cursor는 원자적으로 커밋되며, 중복은 멱등적으로 처리됩니다.",
    steps: [
      {
        title: "High-water mark",
        body: "사용 가능한 이벤트 경계를 캡처합니다.",
      },
      { title: "Catch-up stream", body: "경계까지의 이벤트를 반환합니다." },
      { title: "원자적 커밋", body: "투영과 cursor를 함께 저장합니다." },
      { title: "라이브 계속", body: "위치를 잃지 않고 스트림이 시작됩니다." },
    ],
  },
} satisfies ArchitecturePageCopy;
