import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "개발 상태",
    description: "검증된 GOCODE 구현 증거와 현재 미리보기의 정확한 경계입니다.",
    eyebrow: "개발 상태",
    heading: "지금 작동하는 것, 아직 남은 것.",
    lead: "검증된 구현을 목표 기능, 플랫폼 지원, 릴리스 준비 상태와 분리하여 보여 줍니다.",
    panelLabel: "● 로컬 검증 완료",
    panelTitle: "현재 스냅샷",
    panelBody: "대화 재생 및 계속, 그리고 보호된 로컬 runtime 수명 주기.",
    platform: "macOS arm64 · 개발용 특수 빌드",
  },
  snapshot: {
    eyebrow: "구현 스냅샷",
    heading: "기반이 조립되어 로컬에서 검증되었습니다.",
    lead: "이것은 macOS, Windows 또는 Linux의 운영 지원 증거가 아닙니다.",
    cards: [
      { title: "데스크톱 셸", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "저장소", body: "SQLite · 저널 · 투영" },
      { title: "대화", body: "생성 · 생성 실행 · 재생 · 계속" },
      { title: "로컬 runtime", body: "보호된 socket · 세션 · 재시작" },
    ],
  },
  boundaries: {
    eyebrow: "상태 경계",
    heading: "구현되었다고 릴리스된 것은 아닙니다.",
    lead: "각 미래 기능은 별도로 검증될 때까지 계획으로 남습니다.",
    current: {
      label: "현재",
      title: "구현됨",
      items: [
        "수명 주기 및 인증된 handshake",
        "영속 이벤트 저널",
        "대화 재생 및 계속",
        "안전한 재시도 및 동기화 상태",
      ],
    },
    open: {
      label: "미해결",
      title: "아직 검증되지 않음",
      items: [
        "실제 제공자 및 도구",
        "데스크톱 앱의 TaskRun / Audit",
        "Windows/Linux 및 운영 가능한 macOS 빌드",
        "서명된 설치 관리자 및 공개 릴리스",
      ],
    },
  },
  platforms: {
    eyebrow: "플랫폼 경계",
    heading: "대상 플랫폼은 지원되는 플랫폼이 아닙니다.",
    lead: "특정 릴리스 후보를 패키지 수준에서 검증한 후에만 상태가 변경됩니다.",
    items: [
      { name: "macOS arm64", status: "● 로컬 검증 완료" },
      { name: "Windows", status: "● 적격성 검증 필요" },
      { name: "Linux", status: "● 적격성 검증 필요" },
    ],
  },
} satisfies StatusPageCopy;
