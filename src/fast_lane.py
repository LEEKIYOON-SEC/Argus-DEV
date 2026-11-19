import datetime
import time
from typing import Dict, Iterable, List, Optional, Tuple

import ai_provenance
import enrichment_sources
import feed
import package_index
import pipeline
import risk
import signal_snapshot
import state as pstate
from pages import dashboard_url as _dashboard_url
from collector import Collector
from config import config
from store import Store, create_store
from logger import logger
from notifier import SlackNotifier
from rate_limiter import rate_limit_manager

def _deadline() -> float:
    return time.time() + config.PERFORMANCE["fast_deadline_minutes"] * 60


def _load_signals(collector: Collector) -> Optional[Dict[str, Tuple[float, float]]]:
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    collector.ai_ledger = ai_provenance.load_anthropic_ledger()
    package_index.get()
    return enrichment_sources.load_epss_above(risk.EPSS_P_HIGH)


def _evaluate_changes(changes: List[feed.Change], collector: Collector, db: Store,
                      notifier: SlackNotifier, epss_index, deadline: float,
                      rows: Optional[pipeline.RowCache] = None
                      ) -> Tuple[List[pipeline.Outcome], Dict[str, datetime.datetime],
                                 Dict[str, datetime.datetime]]:
    """(판정 결과, 실패한 CVE 의 배치 시각, 시간이 모자라 손대지 못한 CVE 의 배치 시각).

    손대지 못한 것은 실패가 아니다 — 워터마크만 붙잡고 실패 횟수에는 넣지 않는다.
    실패로 세면 바쁜 회차가 세 번 이어질 때 멀쩡한 CVE 가 격리됐다.
    """
    outcomes: List[pipeline.Outcome] = []
    failed_at: Dict[str, datetime.datetime] = {}
    deferred_at: Dict[str, datetime.datetime] = {}

    for i, change in enumerate(changes):
        if time.time() > deadline:
            logger.warning(f"⏰ 시간 예산 도달 — 잔여 {len(changes) - i}건은 "
                           f"다음 회차 (워터마크가 붙잡는다)")
            for rest in changes[i:]:
                deferred_at[rest.cve_id] = rest.batch_at
            break

        if change.record is None:
            failed_at[change.cve_id] = change.batch_at
            continue
        try:
            st = pipeline.build_state(change.cve_id, change.record, collector, epss_index)
        except Exception as e:
            logger.warning(f"{change.cve_id} 상태 구성 실패: {e}")
            failed_at[change.cve_id] = change.batch_at
            continue
        if st is None:
            try:
                pipeline.retire_rejected(change.cve_id, change.record, db, rows)
            except Exception as e:
                logger.warning(f"{change.cve_id} 철회 반영 실패: {e}")
                failed_at[change.cve_id] = change.batch_at
                continue
            outcomes.append(pipeline.Outcome(change.cve_id, "skipped"))
            continue

        out = pipeline.process(st, db, notifier, rows=rows)
        outcomes.append(out)
        if out.needs_retry:
            failed_at[change.cve_id] = change.batch_at

    return outcomes, failed_at, deferred_at


def _sweep_signals(collector: Collector, db: Store, notifier: SlackNotifier,
                   epss_index, deadline: float,
                   rows: Optional[pipeline.RowCache] = None) -> List[pipeline.Outcome]:
    outcomes: List[pipeline.Outcome] = []
    cap = config.PERFORMANCE["snapshot_cap"]
    for diff in signal_snapshot.sweep(db, fast_only=True, cap=cap):
        if not diff.added:
            continue
        if time.time() > deadline:
            logger.warning(f"⏰ [{diff.source.label}] 시간 예산 도달 — 나머지는 다음 회차")
            break
        targets = {t: signal_snapshot.cve_of(t) for t in diff.added}
        records, absent = feed.fetch_records(
            list(targets.values()), workers=config.PERFORMANCE["max_workers"] * 2)
        processed: List[str] = [t for t, c in targets.items() if c in absent]
        for token, cve_id in targets.items():
            if time.time() > deadline:
                logger.warning(f"⏰ [{diff.source.label}] 시간 예산 도달 — "
                               f"나머지는 다음 회차")
                break
            record = records.get(cve_id)
            if record is None:
                continue
            try:
                st = pipeline.build_state(cve_id, record, collector, epss_index)
            except Exception as e:
                logger.warning(f"{cve_id} 상태 구성 실패: {e}")
                continue
            if st is None:
                processed.append(token)
                continue
            out = pipeline.process(st, db, notifier,
                                   reason_prefix=f"[{diff.source.label}] ", rows=rows)
            outcomes.append(out)
            if not out.needs_retry:
                processed.append(token)
        signal_snapshot.commit(db, diff, processed)
    return outcomes


def _retry_quarantined(changes: List[feed.Change],
                       stamp: datetime.datetime) -> List[feed.Change]:
    """격리 기간이 끝난 CVE 를 이번 회차 대상에 다시 넣는다.

    격리된 CVE 는 워터마크가 이미 지나쳐서, 레코드가 다시 바뀌지 않는 한 변경분에 나오지 않는다.
    여기서 넣지 않으면 '24h 후 자동 재시도'가 일어나지 않는다.
    """
    _fails, quarantined = pstate.read_failure_state()
    held = pstate.active_quarantine(quarantined, config.PERFORMANCE["quarantine_retry_hours"])
    seen = {c.cve_id for c in changes}
    due = [cid for cid in quarantined if cid not in held and cid not in seen]
    if due:
        logger.info(f"격리 해제 재시도 {len(due)}건: {due[:5]}")
    return changes + [feed.Change(cve_id=cid, batch_at=stamp) for cid in due]


def plan_watermark(horizon: datetime.datetime,
                   failed_at: Dict[str, datetime.datetime],
                   deferred_at: Dict[str, datetime.datetime],
                   done: Iterable[str],
                   fails: Dict[str, int], quarantined: Dict[str, str],
                   now: datetime.datetime, max_fail: int, retry_h: int, give_up: int = 7
                   ) -> Tuple[datetime.datetime, Dict[str, int], Dict[str, str], List[str]]:
    """(새 워터마크, 실패 횟수, 격리 목록, 이번에 격리된 CVE).

    - 실패: 횟수를 올리고 max_fail 에 닿으면 격리한다. 격리된 CVE 는 워터마크를 붙잡지 않는다.
    - 격리 중 재시도가 또 실패: 격리 시각을 지금으로 갱신해 retry_h 뒤에 다시 본다. give_up 번 더 실패하면 놓는다.
    - 시간 부족으로 손대지 못한 것: 워터마크만 붙잡는다(횟수를 올리지 않는다).
    - 이번에 처리된 것: 실패 횟수와 격리에서 뺀다.
    """
    fails, quarantined = dict(fails), dict(quarantined)
    now_iso = now.isoformat()
    for cve_id in done:
        fails.pop(cve_id, None)
        quarantined.pop(cve_id, None)

    newly = []
    for cve_id in failed_at:
        fails[cve_id] = fails.get(cve_id, 0) + 1
        if cve_id in quarantined:
            if fails[cve_id] >= max_fail + give_up:
                quarantined.pop(cve_id)
                fails.pop(cve_id)
            else:
                quarantined[cve_id] = now_iso
        elif fails[cve_id] >= max_fail:
            quarantined[cve_id] = now_iso
            newly.append(cve_id)

    blocking = [t for cid, t in failed_at.items() if cid not in quarantined and cid in fails]
    blocking += [t for cid, t in deferred_at.items() if cid not in quarantined]
    new_mark = min(min(blocking) - datetime.timedelta(seconds=1), horizon) if blocking else horizon

    stale = now - datetime.timedelta(days=give_up)
    quarantined = {k: v for k, v in quarantined.items() if pstate.iso_after(v, stale)}
    fails = {k: v for k, v in fails.items() if k in quarantined or k in failed_at}
    return new_mark, fails, quarantined, newly


def _advance_watermark(horizon: datetime.datetime,
                       failed_at: Dict[str, datetime.datetime],
                       deferred_at: Optional[Dict[str, datetime.datetime]] = None,
                       done: Iterable[str] = ()) -> None:
    fails, quarantined = pstate.read_failure_state()
    max_fail = config.PERFORMANCE["max_consecutive_failures"]
    retry_h = config.PERFORMANCE["quarantine_retry_hours"]
    new_mark, fails, quarantined, newly = plan_watermark(
        horizon, failed_at, deferred_at or {}, done, fails, quarantined,
        datetime.datetime.now(datetime.timezone.utc), max_fail, retry_h)
    if newly:
        logger.error(f"⛔ 연속 {max_fail}회 실패로 격리 {len(newly)}건: {newly[:5]} — "
                     f"워터마크 전진을 위해 제외 ({retry_h}h 후 자동 재시도)")
    if new_mark < horizon:
        logger.info(f"실패 · 미처리 {len(failed_at) + len(deferred_at or {})}건 때문에 "
                    f"워터마크를 {new_mark:%m-%d %H:%M:%S}에서 멈춘다")
    pstate.write_watermark(new_mark, failures=fails, quarantined=quarantined,
                           rpd=rate_limit_manager.export_rpd_state())


def run() -> None:
    started = time.time()
    logger.info("=" * 60)
    logger.info("Argus fast-lane 시작")
    logger.info("=" * 60)

    deadline = _deadline()
    collector = Collector()
    db = create_store()
    notifier = SlackNotifier()
    rate_limit_manager.import_rpd_state(pstate.read_rpd_state())

    epss_index = _load_signals(collector)

    watermark = pstate.read_watermark()
    changes, horizon = feed.changes_since(
        watermark, deadline=deadline,
        cap=config.PERFORMANCE["fast_max_changes"])
    changes = _retry_quarantined(changes, watermark or horizon)
    feed.fill_records(changes, workers=config.PERFORMANCE["max_workers"] * 2)

    rows = pipeline.RowCache(db, [c.cve_id for c in changes])
    outcomes, failed_at, deferred_at = _evaluate_changes(changes, collector, db, notifier,
                                                         epss_index, deadline, rows)

    done = [c.cve_id for c in changes if c.cve_id not in failed_at and c.cve_id not in deferred_at]
    _advance_watermark(horizon, failed_at, deferred_at, done)

    if time.time() > deadline:
        logger.warning("⏰ 변경분 처리에 예산을 다 썼다 — 소스측 대조는 다음 회차로 넘긴다")
    else:
        outcomes += _sweep_signals(collector, db, notifier, epss_index, deadline, rows)

    tracked = sum(1 for o in outcomes if o.status == "tracked" and o.fresh)
    notifier.send_batch_summary(dashboard_url=_dashboard_url(), tracked=tracked)
    logger.info(pipeline.summarize(outcomes))
    logger.info(f"fast-lane 완료 · {time.time() - started:.1f}초")


def main() -> None:
    try:
        run()
    except Exception as e:
        logger.error(f"fast-lane 최상위 실패: {e}", exc_info=True)
        try:
            SlackNotifier().send_pipeline_warning(
                "🔴 Argus fast-lane 실패", f"```{type(e).__name__}: {e}```")
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
