from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

from fields import CWE_RE

T0 = "T0"
T1 = "T1"
T2 = "T2"
T3 = "T3"

_TIER_ORDER = {T0: 0, T1: 1, T2: 2, T3: 3}

ALERTING_TIERS = frozenset({T0, T1})


def tier_rank(tier: str) -> int:
    return _TIER_ORDER.get(tier, _TIER_ORDER[T3])


def is_alerting(tier: str) -> bool:
    return tier in ALERTING_TIERS


@dataclass(frozen=True)
class Trigger:
    key: str
    tier: str
    label: str


_TRIGGERS: Tuple[Trigger, ...] = (
    Trigger("kev_ransomware", T0, "CISA KEV 등재 — 랜섬웨어 캠페인에 사용 확인"),
    Trigger("kev", T0, "CISA KEV 등재 — 실제 악용 확인"),
    Trigger("vulncheck_kev", T0, "VulnCheck KEV 등재 — 악용 근거 확보"),
    Trigger("ssvc_active", T0, "CISA SSVC Exploitation=active — 악용 진행형"),

    # Metasploit 모듈은 공격 코드가 공개됐다는 뜻이고 악용이 관측됐다는 뜻은 아니다 — T1(악용 임박)이다(2026-11 T0 에서 옮김).
    # T0 · T1 모두 즉시 알림이라 알림 시점은 같고, 이미 알린 행은 발화 이력이 그대로라 다시 알리지 않는다.
    Trigger("metasploit", T1, "Metasploit 모듈 공개 — 무기화됨"),
    Trigger("nuclei", T1, "nuclei 템플릿 공개 — 대량 스캔·검증 가능"),
    Trigger("exploitdb", T1, "Exploit-DB 공개 익스플로잇 등재"),
    Trigger("epss_critical", T1, "EPSS 상위 1% (p99+) — 악용 확률 최상위"),
    Trigger("ai_discovered", T1, "AI가 발견한 취약점 공개 — 상세가 함께 공개됨"),

    Trigger("cvss_critical_remote", T2, "CVSS 9.0+ · 사전인증 원격 · 무기화 쉬운 유형"),
    Trigger("weaponizable_cwe", T2, "사전인증 원격 + 무기화 비율 높은 취약점 유형(CWE)"),
    Trigger("ssvc_high", T2, "CISA SSVC 자동화 대량 공격 가능 + 완전 장악"),
    Trigger("epss_high", T2, "EPSS 상위 5% (p95+)"),
    Trigger("poc", T2, "PoC 공개 확인"),
    Trigger("unscored_major_cna", T2, "주요 벤더 신규 CVE · 점수 미부여 — 재평가 대기"),
)

TRIGGERS: Dict[str, Trigger] = {t.key: t for t in _TRIGGERS}

ALERTING_TRIGGERS: FrozenSet[str] = frozenset(
    t.key for t in _TRIGGERS if t.tier in ALERTING_TIERS
)


def parse_vector(vector: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not vector or vector == "N/A":
        return out
    for part in str(vector).split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        key, val = key.strip(), val.strip()
        if key and val:
            out.setdefault(key, val)
    return out


def is_remote_unauth(vector: Optional[str]) -> bool:
    m = parse_vector(vector)
    return m.get("AV") == "N" and m.get("PR") == "N"


def is_zero_interaction(vector: Optional[str]) -> bool:
    return is_remote_unauth(vector) and parse_vector(vector).get("UI") == "N"


def is_low_complexity(vector: Optional[str]) -> bool:
    m = parse_vector(vector)
    return m.get("AC") == "L" or m.get("AT") == "N"


WEAPONIZABLE_CWE: FrozenSet[str] = frozenset({
    "CWE-77",
    "CWE-78",
    "CWE-89",
    "CWE-94",
    "CWE-98",
    "CWE-22",
    "CWE-287",
    # 대체 경로 인증 우회 — 지난 1년 KEV(원격·무인증) 9건이 7개 CNA 에서 나왔고, 걸리는 CVE 대비 KEV 비율이
    # 목록 평균의 약 2.7배다(실측 2026-11-18, INVARIANTS §2). 287 · 306 과 같은 사전인증 우회 계열이다.
    "CWE-288",
    "CWE-306",
    "CWE-434",
    "CWE-502",
    "CWE-611",
    "CWE-798",
    "CWE-918",
})

MAJOR_CNAS: FrozenSet[str] = frozenset({
    "microsoft", "cisco", "fortinet", "ivanti", "citrix", "paloaltonetworks",
    "vmware", "broadcom", "oracle", "sap", "adobe", "atlassian", "apache",
    "redhat", "gitlab", "jenkins", "progress", "sonicwall", "zyxel",
    "qnap", "synology", "trendmicro", "zoom", "juniper", "f5", "checkpoint",
    "google", "apple", "mozilla", "jetbrains", "elastic", "hashicorp",
})

EPSS_P_CRITICAL = 0.99
EPSS_P_HIGH = 0.95
EPSS_SCORE_CRITICAL = 0.571
EPSS_SCORE_HIGH = 0.093


def _epss_at(state: Dict, p_threshold: float, score_threshold: float) -> bool:
    pct = state.get("epss_percentile")
    if isinstance(pct, (int, float)) and pct > 0:
        return float(pct) >= p_threshold
    return float(state.get("epss") or 0.0) >= score_threshold


@dataclass(frozen=True)
class Verdict:
    tier: str
    triggers: FrozenSet[str] = field(default_factory=frozenset)


    @property
    def alerting_triggers(self) -> FrozenSet[str]:
        return self.triggers & ALERTING_TRIGGERS


def evaluate(state: Dict) -> Verdict:
    fired = set()
    vector = state.get("cvss_vector")
    cvss = float(state.get("cvss") or 0.0)
    remote_unauth = is_remote_unauth(vector)
    wide_open = is_zero_interaction(vector) and is_low_complexity(vector)
    weaponizable = _has_weaponizable_cwe(state)

    if state.get("is_kev"):
        fired.add("kev")
        if state.get("is_kev_ransomware"):
            fired.add("kev_ransomware")
    if state.get("is_vulncheck_kev"):
        fired.add("vulncheck_kev")
    if state.get("ssvc_exploitation") == "active":
        fired.add("ssvc_active")
    if state.get("has_metasploit_module"):
        fired.add("metasploit")

    if state.get("has_nuclei_template"):
        fired.add("nuclei")
    if state.get("has_public_exploit"):
        fired.add("exploitdb")
    epss_hot = _epss_at(state, EPSS_P_CRITICAL, EPSS_SCORE_CRITICAL)
    if epss_hot:
        fired.add("epss_critical")
    if state.get("ai_discovered"):
        fired.add("ai_discovered")

    epss_warm = _epss_at(state, EPSS_P_HIGH, EPSS_SCORE_HIGH)
    automatable = state.get("ssvc_automatable") == "yes"
    total_impact = state.get("ssvc_technical_impact") == "total"
    if epss_warm:
        fired.add("epss_high")
    if automatable and total_impact:
        fired.add("ssvc_high")
    if state.get("has_poc"):
        fired.add("poc")
    if remote_unauth and weaponizable:
        fired.add("weaponizable_cwe")
    if cvss >= 9.0 and wide_open and (weaponizable or automatable or total_impact
                                      or epss_warm or _is_major_cna(state)):
        fired.add("cvss_critical_remote")
    if cvss <= 0.0 and _is_major_cna(state):
        fired.add("unscored_major_cna")

    tier = min((TRIGGERS[k].tier for k in fired), key=tier_rank, default=T3)
    return Verdict(tier=tier, triggers=frozenset(fired))


def _has_weaponizable_cwe(state: Dict) -> bool:
    cwes = state.get("cwe") or []
    if not isinstance(cwes, (list, tuple)):
        return False
    for raw in cwes:
        for m in CWE_RE.findall(str(raw)):
            if m in WEAPONIZABLE_CWE:
                return True
    return False


def _is_major_cna(state: Dict) -> bool:
    cna = str(state.get("assigner") or "").strip().lower()
    return bool(cna) and cna in MAJOR_CNAS


@dataclass(frozen=True)
class Decision:
    alert: bool
    tier: str
    triggers: FrozenSet[str]
    new_triggers: FrozenSet[str]
    reason: str


def decide(state: Dict, last: Optional[Dict]) -> Decision:
    verdict = evaluate(state)
    already = _previously_fired(last)
    new = verdict.alerting_triggers - already

    reason = " · ".join(TRIGGERS[k].label for k in _ordered(new)) if new else ""
    return Decision(
        alert=bool(new),
        tier=verdict.tier,
        triggers=verdict.triggers,
        new_triggers=new,
        reason=reason,
    )


def _ordered(keys) -> Tuple[str, ...]:
    return tuple(t.key for t in _TRIGGERS if t.key in keys)


def _previously_fired(last: Optional[Dict]) -> FrozenSet[str]:
    if not last:
        return frozenset()
    stored = last.get("fired_triggers")
    if isinstance(stored, (list, tuple, set, frozenset)):
        return frozenset(str(k) for k in stored)
    return evaluate(last).alerting_triggers


def merge_fired(last: Optional[Dict], new_triggers) -> list:
    return sorted(_previously_fired(last) | frozenset(new_triggers))
