import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "로드맵",
    description:
      "GOCODE 로드맵은 릴리스보다 증거를 우선하며 검증되지 않은 가용성을 약속하지 않습니다.",
    eyebrow: "로드맵",
    heading: "먼저 증거, 다음 릴리스.",
    lead: "날짜가 기능을 준비 완료로 만들지 않습니다. 다음 단계에는 구현, 플랫폼 증거, 독립 검토가 필요합니다.",
    panelLabel: "● 미리보기",
    panelTitle: "현재 경계",
    panelBody: "로컬 macOS arm64 경로가 개발용 특수 빌드에서 검증되었습니다.",
    warning: "⚠ 이것은 운영 준비 상태도 공개 릴리스도 아닙니다.",
  },
  stages: {
    eyebrow: "세 단계",
    heading: "모든 단계는 검증으로 완료됩니다.",
    lead: "아직 존재하지 않는 일정을 공개하지 않습니다.",
    cards: [
      {
        label: "01 · 로컬 검증 완료",
        title: "Runtime 기반 완료",
        body: "영속적 대화, 재생 및 계속, 재시작 후 복구.\nmacOS arm64 · 개발용 특수 빌드",
      },
      {
        label: "02 · 다음",
        title: "실제 에이전트 프로세스",
        body: "실제 제공자, TaskRun/Audit 스트림, 확장된 작업 공간.\n기준: contract + 복구",
      },
      {
        label: "03 · 공개 릴리스 전",
        title: "운영 준비",
        body: "네이티브 격리, 서명, Windows/Linux 적격성 검증, 독립적 판정.",
      },
    ],
  },
  exclusions: {
    eyebrow: "아직 약속하지 않는 것",
    heading: "계획은 사용 가능한 기능 목록이 아닙니다.",
    items: [
      {
        title: "실제 모델을 이용한 프로덕션 실행 없음",
        body: "현재 제공자는 결정론적이고 로컬입니다.",
      },
      {
        title: "공개 다운로드 없음",
        body: "서명, 설치 관리자, 적격성 검증이 미완료입니다.",
      },
      {
        title: "검증된 크로스 플랫폼 지원 없음",
        body: "Windows/Linux에는 별도 증거가 필요합니다.",
      },
    ],
  },
  legend: {
    eyebrow: "상태 읽는 법",
    heading: "색상은 증거의 종류를 나타냅니다.",
    cards: [
      {
        label: "● 로컬 검증 완료",
        title: "",
        body: "명시된 환경에 구현과 정확한 증거가 있습니다.",
      },
      {
        label: "● 다음",
        title: "",
        body: "이 슬라이스는 정의되었지만 아직 사용 가능한 기능이 아닙니다.",
      },
      {
        label: "● 공개 릴리스 전",
        title: "",
        body: "필수 적격성 검증 및 릴리스 조건입니다.",
      },
    ],
  },
} satisfies RoadmapPageCopy;
