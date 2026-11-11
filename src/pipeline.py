from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import pytz

import risk
from fields import meaningful
from logger import logger

KST = pytz.timezone('Asia/Seoul')

STATE_FIELDS = frozenset({
    "title", "title_ko", "description", "desc_ko", "cwe", "affected", "published",
    "cvss_vector",
    "references", "_nuclei_url", "_exploit_db_url",
    "is_kev", "is_kev_ransomware", "kev_due_date", "is_vulncheck_kev",
    "ssvc", "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
    "has_poc", "poc_urls", "has_public_exploit",
    "has_metasploit_module", "metasploit_modules",
    "has_nuclei_template", "nuclei_severity",
    "ai_discovered", "ai_program", "ai_detail", "ai_url", "analysis",
    "cvss", "cvss_version", "cvss_scores", "epss", "epss_percentile", "assigner",
    "tier", "fired_triggers",
    # 번역을 시도했지만 한국어로 돌아오지 않은 제목(원문) — 같은 제목이면 다시 시도하지 않는다(main.translate_tracked).
    "ko_tried",
})


@dataclass
class Outcome:
    cve_id: str
    status: str
    tier: str = risk.T3
    # 이번에 처음 추적 목록에 들어왔는가 — 요약의 '관찰 등록' 건수는 이것만 센다(다시 저장한 행은 세지 않는다).
    fresh: bool = False


    @property
    def needs_retry(self) -> bool:
        return self.status == "failed"


    @property
    def alerted(self) -> bool:
        return self.status == "alerted"


def build_state(cve_id: str, record: Dict, collector,
                epss_index: Optional[Dict[str, Tuple[float, float]]] = None
                ) -> Optional[Dict]:
    raw = collector.parse_record(cve_id, record)
    if raw.get('state') == 'ERROR':
        raise RuntimeError(f"{cve_id} 레코드 파싱 실패")
    if raw.get('state') != 'PUBLISHED':
        return None

    collector.enrich_cheap_signals(raw)

    if collector.kev_loaded:
        raw["is_kev"] = cve_id in collector.kev_set
        raw["kev_due_date"] = collector.kev_due_date.get(cve_id, "")
    if epss_index is not None and cve_id in epss_index:
        raw["epss"], raw["epss_percentile"] = epss_index[cve_id]
    return raw


def retire_rejected(cve_id: str, record: Dict, db, rows: Optional["RowCache"] = None) -> bool:
    """CVE 가 철회(REJECTED)됐으면 추적 목록에서 내린다 — 내렸으면 True.

    철회된 레코드는 build_state 가 건너뛰므로, 그대로 두면 철회 전의 내용이 보존 기간(90일) 동안 화면에 남는다.
    행은 지우지 않고 상태만 비운다(알림 이력은 남는다).
    """
    if ((record or {}).get("cveMetadata") or {}).get("state") != "REJECTED":
        return False
    row = rows.get(cve_id) if rows is not None else db.get_cve(cve_id)
    if not (row or {}).get("last_alert_state"):
        return False
    if not db.blank_states([cve_id]):
        return False
    if rows is not None:
        rows.forget(cve_id)
    logger.info(f"{cve_id}: 철회(REJECTED)된 CVE — 추적 목록에서 내린다")
    return True


class RowCache:
    __slots__ = ("_db", "_rows", "_covered")


    def __init__(self, db, cve_ids=()):
        self._db = db
        self._rows: Dict[str, Dict] = {}
        self._covered: set = set()
        ids = list(dict.fromkeys(cve_ids))
        if ids:
            self._rows, self._covered = db.get_cves(ids)
            logger.info(f"기존 행 일괄 조회 {len(self._rows)}/{len(ids)}건 "
                        f"(개별 왕복 {len(self._covered)}회 절약)")


    def get(self, cve_id: str) -> Optional[Dict]:
        row = self._rows.get(cve_id)
        if row is not None:
            return row
        if cve_id in self._covered:
            return None
        return self._db.get_cve(cve_id)


    def forget(self, cve_id: str) -> None:
        self._rows.pop(cve_id, None)
        self._covered.discard(cve_id)


_CVSS_KEYS = ("cvss", "cvss_vector", "cvss_version", "cvss_scores")


def _knows_affected(rows: List[Dict]) -> bool:
    return any(meaningful(a.get("product")) or meaningful(a.get("vendor"))
               for a in rows)


def _carry_affected(state: Dict, last: Dict) -> None:
    prev = [a for a in (last.get("affected") or []) if isinstance(a, dict)]
    if not _knows_affected(prev):
        return
    rows = [a for a in (state.get("affected") or []) if isinstance(a, dict)]
    if not _knows_affected(rows):
        state["affected"] = prev
        return

    by_product: Dict[str, str] = {}
    vendors = set()
    for a in prev:
        vendor = meaningful(a.get("vendor"))
        if not vendor:
            continue
        vendors.add(vendor)
        product = meaningful(a.get("product")).lower()
        if product:
            by_product.setdefault(product, vendor)
    if not vendors:
        return

    sole = next(iter(vendors)) if len(vendors) == 1 else ""
    for a in rows:
        if meaningful(a.get("vendor")):
            continue
        vendor = by_product.get(meaningful(a.get("product")).lower()) or sole
        if vendor:
            a["vendor"] = vendor
    state["affected"] = rows


def carry_forward(state: Dict, last: Optional[Dict]) -> Dict:
    if not isinstance(last, dict):
        return state
    for key in STATE_FIELDS:
        if key not in state and key in last:
            state[key] = last[key]
    if (float(state.get("cvss") or 0.0) <= 0.0 and not state.get("cvss_scores")
            and float(last.get("cvss") or 0.0) > 0.0):
        for key in _CVSS_KEYS:
            if key in last:
                state[key] = last[key]
    _carry_affected(state, last)
    return state


def process(state: Dict, db, notifier, *, reason_prefix: str = "",
            make_report=None, rows: Optional["RowCache"] = None,
            silent: bool = False) -> Outcome:
    cve_id = state['id']
    try:
        last_row = rows.get(cve_id) if rows is not None else db.get_cve(cve_id)
        last = (last_row or {}).get('last_alert_state')
        carry_forward(state, last)
        decision = risk.decide(state, last)

        if decision.tier == risk.T3:
            if last is not None:
                _save(db, state, decision, last, alerted=False)
                if rows is not None:
                    rows.forget(cve_id)
                return Outcome(cve_id, "tracked", decision.tier)
            return Outcome(cve_id, "skipped", decision.tier)

        announce = decision.alert and not silent
        rules_info = None
        if announce and make_report is not None and not state.get('analysis'):
            analysis, rules_info = make_report(state, decision.reason)
            if analysis:
                state['analysis'] = analysis

        sent = True
        if announce:
            reason = f"{reason_prefix}{decision.reason}" if reason_prefix else decision.reason
            sent = notifier.send_alert(state, reason, tier=decision.tier) is not False
            if not sent:
                logger.error(f"{cve_id} Slack 전송 실패 — 발화 이력을 남기지 않는다 "
                             f"(다음 회차가 다시 알린다)")

        new_triggers = decision.new_triggers if sent else frozenset()
        if not _save(db, state, decision, last, alerted=announce and sent,
                     new_triggers=new_triggers, rules_info=rules_info):
            return Outcome(cve_id, "failed", decision.tier)

        if rows is not None:
            rows.forget(cve_id)
        return Outcome(cve_id, "alerted" if (announce and sent) else "tracked",
                       decision.tier, fresh=last is None)

    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        return Outcome(cve_id, "failed")


def _save(db, state: Dict, decision: risk.Decision, last: Optional[Dict],
          alerted: bool, rules_info: Optional[Dict] = None,
          new_triggers=None) -> bool:
    now = datetime.datetime.now(KST).isoformat()
    clean = {k: state[k] for k in STATE_FIELDS if k in state}
    clean["tier"] = decision.tier
    clean["fired_triggers"] = risk.merge_fired(
        last, decision.new_triggers if new_triggers is None else new_triggers)

    payload = {
        "id": state['id'],
        "cvss_score": state.get('cvss', 0.0),
        "epss_score": state.get('epss', 0.0),
        "is_kev": bool(state.get('is_kev')),
        "last_alert_state": clean,
        "updated_at": now,
    }
    if alerted:
        payload["last_alert_at"] = now
    if rules_info:
        payload["has_official_rules"] = rules_info.get('has_official', False)
        payload["rules_snapshot"] = rules_info.get('rules')
        payload["last_rule_check_at"] = now
    return db.upsert_cve(payload)


def summarize(outcomes: List[Outcome]) -> str:
    by_tier: Dict[str, int] = {}
    for o in outcomes:
        if o.status in ("alerted", "tracked"):
            by_tier[o.tier] = by_tier.get(o.tier, 0) + 1
    alerted = sum(1 for o in outcomes if o.alerted)
    failed = sum(1 for o in outcomes if o.needs_retry)
    skipped = sum(1 for o in outcomes if o.status == "skipped")
    tiers = " · ".join(f"{t} {by_tier[t]}" for t in (risk.T0, risk.T1, risk.T2)
                       if by_tier.get(t))
    return (f"판정 {len(outcomes)}건 → 알림 {alerted} · 추적 {sum(by_tier.values())}"
            f"{f' ({tiers})' if tiers else ''} · 미저장 {skipped} · 실패 {failed}")
