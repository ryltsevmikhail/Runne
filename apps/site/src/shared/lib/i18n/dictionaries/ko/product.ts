import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "제품",
    description:
      "GOCODE는 로컬 프로젝트, 대화, runtime 상태를 하나의 데스크톱 앱에 모읍니다.",
    eyebrow: "제품",
    heading: "AI 에이전트 작업을 위한 하나의 제어 센터.",
    lead: "로컬 프로젝트를 열고, 대화를 이어가며, 재시작 후에도 계속 작업할 수 있습니다. 권위 있는 상태를 보존하는 것은 앱 창이 아니라 GOCODE runtime입니다.",
    boundary:
      "● 미리보기: macOS arm64, 결정론적 제공자, 프로덕션 모델 실행 없음.",
    cta: "대기자 명단 참여",
    mockup: {
      ariaLabel: "GOCODE 로컬 프로젝트 인터페이스",
      topLabel: "GOCODE · 로컬 프로젝트",
      status: "● runtime 준비 완료",
      railTitle: "프로젝트",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "에이전트 대화",
      state: "LEAD · 복원됨",
      message: "확인된 상태에서 중복 없이 대화를 이어갔습니다.",
      input: "GOCODE에 프로젝트 작업 요청…",
    },
  },
  workflow: {
    eyebrow: "워크플로",
    heading: "로컬 폴더에서 이어갈 수 있는 대화까지.",
    lead: "폴더는 기기에 남습니다. GOCODE는 로컬 프로젝트 기록과 작업 상태를 저장합니다.",
    steps: [
      { title: "프로젝트 열기", body: "기기의 로컬 폴더를 선택합니다." },
      { title: "대화 시작", body: "현재 로컬 대화에서 요청을 보냅니다." },
      { title: "상태 커밋", body: "이벤트가 runtime 저널에 영속화됩니다." },
      { title: "작업 계속", body: "재시작 또는 연결 해제 후 돌아옵니다." },
    ],
  },
  workspace: {
    eyebrow: "작업 공간",
    heading: "프로젝트, 대화, runtime 상태를 한 창에.",
    lead: "인터페이스는 타입이 지정되고 정제된 데이터만 표시합니다. 시크릿과 raw runtime 오류는 view model에 절대 들어가지 않습니다.",
    items: [
      {
        title: "로컬 프로젝트",
        body: "최근 작업 폴더와 명시적인 프로젝트 선택.",
      },
      {
        title: "이어갈 수 있는 대화",
        body: "재생, 라이브 피드, 안전한 동기화.",
      },
      { title: "Runtime 상태", body: "시작, 준비, 재시작, 성능 저하, 복구." },
    ],
  },
} satisfies ProductPageCopy;
