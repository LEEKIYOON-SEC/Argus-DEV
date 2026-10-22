"""색인에는 있는데 화면(룰 스냅샷)에 없는 룰 채우기 (INVARIANTS §6).

룰 스냅샷은 CVE 를 분석하거나 다시 확인할 때만 만든다. 그래서 주간 색인(build_rule_index)에 새 룰이 들어와도 룰이
하나라도 있던 CVE 는 그대로였다. 색인이 '룰이 늘어난 CVE' 목록을 적어 넘기던 방식은 매시 실행이 그 목록을 다 보기 전에
색인을 다시 만들면 남은 CVE 를 잃었다(2026-10-22 운영 색인은 목록이 비어 CVE-2026-109618 의 Snort 룰이 화면에 나오지
않았다). 그래서 매시 실행이 대시보드에 나오는 CVE 의 스냅샷을 지금 색인과 직접 견준다 — 지금 색인으로 다시 찾으면
들어올 룰(rule_manager.missing)이 스냅샷에 없으면 다시 본다.

같은 색인으로는 CVE 마다 한 번만 본다: 마지막으로 본 시각이 색인을 만든 시각(generated_at)보다 SETTLE 이상 뒤면
넘어간다. 만든 직후에 본 것은 배포 · 캐시 때문에 옛 색인으로 봤을 수 있어 한 번 더 본다.

- 룰이 없던 CVE: 지금처럼 알림 예산(max_rule_recheck) 안에서 먼저 보고, 찾으면 Slack 을 보낸다.
- 이미 룰이 있던 CVE: 알림 없이 스냅샷만 바꾼다 — '룰이 없던 CVE 에서 발견' 알림의 뜻과 맞지 않는다.
"""
import datetime
import time
from typing import Callable, Dict, List, Optional, Tuple

from logger import logger

RULE_KEYS = ("network", "sigma", "yara", "nuclei", "splunk")
SETTLE = datetime.timedelta(hours=1)


def _when(ts) -> Optional[datetime.datetime]:
    try:
        d = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def _order(row: Dict):
    # 중요한 것부터 — 기존 재확인(get_rule_recheck_candidates)과 같은 순서.
    return (not row.get("is_kev"), -(row.get("cvss_score") or 0), -(row.get("epss_score") or 0), row["id"])


def due(rows: Dict[str, Dict], built_at: str,
        missing: Callable[[str, object], bool]) -> Tuple[List[Dict], List[Dict]]:
    """스냅샷에 지금 색인의 룰이 빠졌고 이 색인으로 아직 다시 보지 않은 CVE — (룰이 없던 것, 이미 룰이 있던 것)."""
    built = _when(built_at)
    if built is None:
        return [], []
    fresh: List[Dict] = []
    known: List[Dict] = []
    for row in rows.values():
        last = _when(row.get("last_rule_check_at"))
        if last is not None and last >= built + SETTLE:
            continue
        if not missing(row["id"], row.get("rules_snapshot")):
            continue
        (known if row.get("has_official_rules") else fresh).append(row)
    return sorted(fresh, key=_order), sorted(known, key=_order)


def plan(db, ids: List[str], built_at: str, max_recheck: int,
         missing: Callable[[str, object], bool]) -> Tuple[List[Dict], List[Dict]]:
    """알림을 보낼 수 있는 재확인 대상(룰이 빠진 CVE 먼저, 남는 자리는 기존 대상)과 조용히 바꿀 대상."""
    fresh: List[Dict] = []
    known: List[Dict] = []
    if ids and built_at:
        try:
            fresh, known = due(db.get_rule_rows(ids), built_at, missing)
            logger.info(f"색인에는 있는데 화면에 없는 룰 — 룰이 없던 CVE {len(fresh):,}건 · "
                        f"이미 룰이 있던 CVE {len(known):,}건")
        except Exception as e:
            logger.warning(f"룰이 빠진 CVE 조회 실패({e}) — 기존 재확인만 한다")
    fresh = fresh[:max(0, max_recheck)]
    picked = {r["id"] for r in fresh}
    rest = max_recheck - len(fresh)
    regular = [r for r in db.get_rule_recheck_candidates(limit=rest) if r["id"] not in picked] if rest > 0 else []
    return fresh + regular, known


def refresh_known(db, search: Callable[[str], Tuple[Dict, bool]], rows: List[Dict],
                  now: Callable[[], str], soon: Callable[[], str],
                  deadline_ts: Optional[float] = None,
                  clock: Optional[Callable[[], float]] = None) -> int:
    """이미 룰이 있던 CVE 의 스냅샷을 지금 색인으로 다시 만든다. 알림은 보내지 않는다. 바꾼 건수를 돌려준다."""
    clock = clock or time.time
    done = 0
    for row in rows:
        if deadline_ts is not None and clock() > deadline_ts:
            logger.warning("⏰ 시간 예산 도달 — 룰 스냅샷 갱신 중단 (남은 CVE 는 다음 실행이 이어받는다)")
            break
        cve_id = row["id"]
        try:
            rules, complete = search(cve_id)
        except Exception as e:
            logger.error(f"{cve_id} 룰 스냅샷 갱신 실패: {e}")
            continue
        stamp = now()
        if not complete:
            # 원문을 다 못 받았다 — 이전 스냅샷을 지키고 곧 다시 본다.
            db.upsert_cve({"id": cve_id, "last_rule_check_at": soon(), "updated_at": stamp})
            continue
        if any(rules.get(k) for k in RULE_KEYS):
            db.upsert_cve({"id": cve_id, "has_official_rules": True, "rules_snapshot": rules,
                           "last_rule_check_at": stamp, "updated_at": stamp})
            done += 1
        else:
            # 색인에서 룰이 사라졌어도 이전 스냅샷은 지우지 않는다 — 못 찾은 것을 '룰 없음'으로 만들지 않는다.
            db.upsert_cve({"id": cve_id, "last_rule_check_at": stamp, "updated_at": stamp})
    return done
