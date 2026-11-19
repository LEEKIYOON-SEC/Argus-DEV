from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

import ai_provenance
import enrichment_sources
import risk
from logger import logger

@dataclass(frozen=True)
class Source:
    key: str
    label: str
    fast: bool
    load: Callable[[], Optional[Set[str]]]
    # 처음 기록할 때 '이미 본 것'으로 두지 않고 바로 판정할 ID 를 고른다 — (upstream, store) → 집합.
    # 없으면 기존대로 전량을 본 것으로 둔다(첫 실행 알림 폭풍 방지, INVARIANTS §3).
    catch_up: Optional[Callable[[Set[str], object], Set[str]]] = None
    # 상한(cap)에 걸리면 최신 CVE(연도 · 번호가 큰 것)부터 처리한다. 기본은 ID 오름차순.
    newest_first: bool = False


_RANSOM_SUFFIX = "#ransomware"


def cve_of(token: str) -> str:
    return token.split("#", 1)[0]


def _kev_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_cisa_kev()
    if data is None:
        return None
    out: Set[str] = set()
    for cve_id, item in data.items():
        out.add(cve_id)
        if str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known":
            out.add(cve_id + _RANSOM_SUFFIX)
    return out


def _vulncheck_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_vulncheck_kev()
    return None if data is None else set(data)


def _nuclei_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_nuclei_index()
    return set(idx) or None


def _metasploit_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_metasploit_index()
    return set(idx) or None


def _exploitdb_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_exploitdb_index()
    return set(idx) or None


def _epss_critical_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_epss_full()
    if not data:
        return None
    return {cve for cve, (_score, pct) in data.items() if pct >= risk.EPSS_P_CRITICAL}


def _anthropic_cvd_ids() -> Optional[Set[str]]:
    data = ai_provenance.load_anthropic_ledger()
    return None if data is None else (set(data) or None)


def _poc_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_poc_index()
    return set(idx) or None


POC_CATCH_UP_DAYS = 90


def _poc_catch_up(ids: Set[str], store) -> Set[str]:
    """PoC 소스를 처음 기록할 때 바로 판정할 것 — 공개 90일 이내이거나 날짜가 없는 CVE 중 아직 추적하지 않는 것.

    PoC 는 레코드가 바뀔 때만 확인해 왔다. 처음 기록 때 전부 '본 것'으로 두면, 이미 PoC 가 있는데 T3 로 지나간
    CVE 가 그대로 남는다(실측 2026-11-18: 공개 90일 이내 347건, CVE-2026-114938 포함).
    날짜가 없는 것은 PoC-in-GitHub 가 아직 공개일을 받지 못한 것(공개 직후 · 공개 전)이거나 형식이 틀린 ID 다 —
    공개 전 · 형식 오류는 레코드가 없어(404) 본 것으로 넘어간다.
    90일보다 넓히면 오래된 CVE 가 '방금 갱신됨'으로 대시보드에 한꺼번에 올라온다.
    이미 추적 중인 것은 다시 저장하지 않는다 — 갱신 시각만 바뀌어 목록 위로 몰린다.
    """
    dates = enrichment_sources.poc_dates()
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=POC_CATCH_UP_DAYS)).date().isoformat()
    recent = sorted(c for c in ids if dates.get(c, "9999-12-31") >= cutoff)
    if not recent:
        return set()
    rows, _covered = store.get_cves(recent)
    tracked = {c for c, row in rows.items() if (row or {}).get("last_alert_state")}
    return set(recent) - tracked


_CVE_NUM = re.compile(r"CVE-(\d{4})-(\d+)", re.I)


def _newest(token: str):
    m = _CVE_NUM.match(cve_of(token))
    return (int(m.group(1)), int(m.group(2)), token) if m else (0, 0, token)


def _ordered(source: Source, ids) -> List[str]:
    return sorted(ids, key=_newest, reverse=True) if source.newest_first else sorted(ids)


SOURCES: Dict[str, Source] = {
    s.key: s for s in (
        Source("cisa_kev_v2", "CISA KEV", True, _kev_ids),
        Source("vulncheck_kev", "VulnCheck KEV", True, _vulncheck_ids),
        Source("nuclei", "nuclei 템플릿", False, _nuclei_ids),
        Source("metasploit", "Metasploit 모듈", False, _metasploit_ids),
        Source("exploitdb", "Exploit-DB", False, _exploitdb_ids),
        Source("epss_critical", f"EPSS p{risk.EPSS_P_CRITICAL:.0%}", False,
               _epss_critical_ids),
        Source("anthropic_cvd", "Anthropic CVD (ANT)", False,
               _anthropic_cvd_ids),
        # PoC 는 T2(관찰) 근거라 매시 bulk-lane 이면 충분하다. 레코드가 바뀐 뒤에 PoC 가 생긴 CVE 를 다시 판정한다.
        Source("poc_in_github", "PoC-in-GitHub", False, _poc_ids,
               catch_up=_poc_catch_up, newest_first=True),
    )
}


def digest_of(ids: Set[str]) -> str:
    h = hashlib.sha256()
    for cve in sorted(ids):
        h.update(cve.encode())
        h.update(b"\n")
    return h.hexdigest()


@dataclass
class Diff:
    source: Source
    added: List[str]
    known: Set[str] = field(default_factory=set)


def sweep(store, cap: int, fast_only: bool = False,
          only: Optional[List[str]] = None) -> List[Diff]:
    results: List[Diff] = []
    for key, source in SOURCES.items():
        if only is not None and key not in only:
            continue
        if fast_only and not source.fast:
            continue
        try:
            diff = _sweep_one(store, source, cap)
        except Exception as e:
            logger.error(f"[{source.label}] 스냅샷 대조 실패: {e}")
            continue
        if diff is not None:
            results.append(diff)
    return results


def _sweep_one(store, source: Source, cap: int) -> Optional[Diff]:
    upstream = source.load()
    if upstream is None:
        logger.warning(f"[{source.label}] 수신 실패 → 이번 회차 대조 생략 "
                       f"(빈 집합으로 저장하지 않는다)")
        return None

    new_digest = digest_of(upstream)
    stored_digest = store.get_snapshot_digest(source.key)

    if stored_digest is None:
        pending = (set(source.catch_up(upstream, store)) & upstream) if source.catch_up else set()
        known = upstream - pending
        if not known:
            # 전부 판정 대상이면 '본 것'이 비어 다음 회차가 집합을 읽지 못한다 — 이번은 기록만 한다.
            known, pending = upstream, set()
        store.save_snapshot(source.key, digest_of(known), known)
        if not pending:
            logger.info(f"[{source.label}] 스냅샷 최초 기록 {len(upstream):,}건 — 알림 없음")
            return Diff(source=source, added=[])
        picked = _ordered(source, pending)[:cap]
        logger.info(f"[{source.label}] 스냅샷 최초 기록 {len(known):,}건 · 바로 판정할 것 {len(pending):,}건 "
                    f"(이번 {len(picked)}건, 나머지는 다음 실행)")
        return Diff(source=source, added=picked, known=known)

    if stored_digest == new_digest:
        logger.debug(f"[{source.label}] 변화 없음 (digest 일치)")
        return None

    known = store.get_snapshot_ids(source.key)
    if not known:
        logger.warning(f"[{source.label}] 저장된 집합을 읽지 못함 → 이번 회차 생략")
        return None

    added = _ordered(source, upstream - known)
    if not added:
        store.save_snapshot(source.key, digest_of(known | upstream), known | upstream)
        logger.info(f"[{source.label}] 신규 없음 (제외분만 변동)")
        return None

    picked = added[:cap]
    if len(added) > cap:
        logger.warning(f"[{source.label}] 신규 {len(added):,}건 중 {cap}건만 이번에 처리 "
                       f"— 나머지는 다음 실행이 이어받는다")
    logger.info(f"🚨 [{source.label}] 신규 {len(picked)}건: {picked[:5]}"
                f"{' …' if len(picked) > 5 else ''}")
    return Diff(source=source, added=picked, known=known)


def commit(store, diff: Diff, processed: List[str]) -> None:
    if not processed:
        return
    if not diff.known:
        logger.error(f"[{diff.source.label}] 직전 집합이 비어 있다 — 스냅샷을 갱신하지 않는다 "
                     f"(축소 저장은 다음 회차 알림 폭풍이 된다)")
        return
    merged = diff.known | set(processed)
    if not store.save_snapshot(diff.source.key, digest_of(merged), merged):
        logger.error(f"[{diff.source.label}] 스냅샷 저장 실패 — 다음 회차가 다시 처리한다")
        return
    logger.info(f"[{diff.source.label}] 스냅샷 갱신: {len(diff.known):,} → {len(merged):,}건")
