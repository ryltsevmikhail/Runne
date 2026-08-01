import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "AI 코딩 에이전트 — 당신의 통제 아래",
    description:
      "GOCODE는 검증 가능한 경계를 갖춘 로컬 runtime을 기반으로 하는 AI 에이전트용 데스크톱 제어 센터입니다.",
    eyebrow: "미리보기",
    heading: "AI 코딩 에이전트 — 당신의 통제 아래.",
    lead: "GOCODE는 데스크톱 제어 센터이자 provider-neutral Rust runtime입니다. 권위 있는 상태를 보존하고 재시작 후 대화를 복원합니다.",
    cta: "대기자 명단 참여",
    mockup: {
      ariaLabel: "GOCODE 인터페이스 예시",
      topLabel: "GOCODE · 로컬 runtime",
      status: "● runtime 준비 완료",
      railTitle: "프로젝트",
      project: "agent-runtime",
      railItems: ["crates", "docs · tests"],
      chatTitle: "에이전트 대화",
      state: "LEAD · 복원됨",
      message: "runtime 경계를 확인하고 안전한 변경 계획을 준비했습니다.",
      input: "GOCODE에 프로젝트 작업 요청…",
    },
  },
  why: {
    eyebrow: "GOCODE를 선택하는 이유",
    heading: "에이전트 워크플로는 창이 닫힌다고 사라져서는 안 됩니다.",
    lead: "GOCODE는 편리한 데스크톱 앱과 권위 있는 상태를 분리합니다. 작업은 취약한 UI 세션이 아니라 runtime의 일부로 계속됩니다.",
    items: [
      {
        title: "재시작해도 프로세스는 끝나지 않습니다",
        body: "대화와 이벤트를 영속 스트림에서 복원합니다.",
      },
      {
        title: "인터페이스가 진실을 소유하지 않습니다",
        body: "runtime은 확인된 투영만 노출합니다.",
      },
      {
        title: "불확실한 상태는 동작을 막습니다",
        body: "변경은 확인된 후에만 시작됩니다.",
      },
    ],
  },
  architecture: {
    eyebrow: "아키텍처",
    heading: "하나의 runtime. 하나의 신뢰할 수 있는 정보원.",
    lead: "데스크톱 앱은 공개 runtime client와 contract API만 호출합니다. 구현 내부는 프로세스 경계 뒤에 남습니다.",
    flow: [
      { title: "앱", body: "인터페이스" },
      { title: "Tauri host", body: "신뢰 경계" },
      { title: "runtime-client", body: "공개 API" },
      { title: "GOCODE runtime", body: "권위 있는 상태" },
      { title: "이벤트 저널", body: "영속 기록" },
    ],
  },
  preview: {
    eyebrow: "미리보기",
    heading: "실제 모델을 연결하기 전에 기반을 증명합니다.",
    lead: "현재 증거: macOS arm64 · 개발용 특수 빌드.",
    verified: {
      label: "● 검증됨",
      title: "현재 버전에서 작동하는 기능",
      items: [
        "인증된 runtime 수명 주기",
        "영속 저널 및 이벤트 재생",
        "대화 복원 및 계속",
        "Vue + Tauri 데스크톱 셸",
      ],
    },
    review: {
      label: "● 검토 중",
      title: "정직한 버전 경계",
      items: [
        "실제 모델 대신 결정론적 제공자",
        "서명된 설치 관리자 없음",
        "Windows/Linux 운영 준비 미완료",
      ],
    },
  },
  roadmap: {
    eyebrow: "로드맵",
    heading: "먼저 증거, 다음 확장.",
    lead: "일정 약속은 하지 않습니다. 각 단계는 검증 가능한 릴리스 기준을 충족해야 완료됩니다.",
    cards: [
      {
        label: "01 · 현재 단계",
        title: "Runtime 기반 완료",
        body: "수명 주기, 이벤트 저널, 대화 복구, 데스크톱 셸.",
      },
      {
        label: "02 · 다음",
        title: "실제 에이전트 프로세스",
        body: "실제 제공자, TaskRun/Audit 스트림, 확장된 작업 공간.",
      },
      {
        label: "03 · 릴리스 전",
        title: "준비 상태 적격성 검증",
        body: "네이티브 격리, 서명, 플랫폼 적격성 검증, 독립적 판정.",
      },
    ],
  },
} satisfies HomePageCopy;
