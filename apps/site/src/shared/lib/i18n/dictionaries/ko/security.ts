import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "보안",
    description:
      "불확실한 상태에는 동작 권한을 부여하지 않습니다. GOCODE의 보안 경계는 검증 가능합니다.",
    eyebrow: "보안",
    heading: "불확실한 상태에는 동작 권한을 부여하지 않습니다.",
    lead: "GOCODE는 명시적 신뢰 경계, 무결성 검사, 증거가 부족할 때의 안전한 종료로 로컬 경계를 구축합니다.",
    panelEyebrow: "로컬 경계",
    panelBody: "자격 증명과 엔드포인트는 인터페이스에 전달되지 않습니다.",
  },
  trust: {
    eyebrow: "신뢰 맵",
    heading: "모든 경계는 무엇을 신뢰해야 하는지 알고 있습니다.",
    lead: "소유자, 채널, 무결성 검사는 상태 변경 전에 수행됩니다.",
    cards: [
      {
        title: "인터페이스",
        body: "정제되고 타입이 지정된 데이터만 받습니다.",
        label: "시크릿을 저장하지 않음",
      },
      {
        title: "로컬 프로필",
        body: "Unix/macOS 미리보기에서 소유자, 파일 모드, loopback 주소를 확인합니다.",
        label: "Windows: 네이티브 ACL 전까지 거부",
      },
      {
        title: "이벤트 저널",
        body: "순서, 무결성, cursor를 검증합니다.",
        label: "영속 기록",
      },
    ],
  },
  mechanisms: {
    eyebrow: "검증 가능한 메커니즘",
    heading: "보호는 구체적인 거부로 구축됩니다.",
    lead: "어느 한 항목도 미래의 독립 보안 검토를 대체할 수 없습니다.",
    cards: [
      {
        title: "재생 무결성",
        body: "HMAC cursor, high-water mark, 시퀀스 검증.",
      },
      {
        title: "원자적 복구",
        body: "전달을 확인하기 전에 투영과 cursor를 커밋합니다.",
      },
      {
        title: "안전하지 않은 시작 차단",
        body: "인증된 Phase 6B 프로필이 존재할 때까지 프로세스 시작은 거부됩니다.",
      },
      {
        title: "시크릿 broker",
        body: "권한 부여, 버전, 가용성, 해지를 확인합니다.",
      },
      { title: "멱등성", body: "재전달해도 중복 상태가 생성되지 않습니다." },
      {
        title: "권한 없는 제공자",
        body: "현재 결정론적 제공자는 네트워크, 파일 또는 프로세스 접근 권한이 없습니다.",
      },
    ],
  },
  boundary: {
    eyebrow: "정직한 경계",
    heading: "이것은 운영 보안 인증이 아닙니다.",
    lead: "Phase 6B 네이티브 격리, Windows/Linux 적격성 검증, 실제 제공자, 독립 검토는 아직 완료되지 않았습니다.",
    items: ["네이티브 격리", "크로스 플랫폼 적격성 검증", "독립적인 최종 판정"],
    roadmapCta: "로드맵 보기",
  },
} satisfies SecurityPageCopy;
