import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import ai_provenance
import config
import risk
import seed_turso
import signal_snapshot
import state as pstate
from collector import Collector
from logger import logger
from store import create_store

_CAP = config.config.PERFORMANCE["snapshot_cap"]


def _pct(n: int, total: int) -> str:
    return f"{n:,} ({n / total * 100:.0f}%)" if total else "0"


def main() -> int:
    logger.info("=" * 60)
    logger.info("재시드 검증 — 컷오버해도 되는가")
    logger.info("=" * 60)

    db = create_store()
    pstate._DB_HANDLE = db
    blockers, warnings = [], []

    stats = db.seed_stats()
    total = sum(s["rows"] for s in stats)
    logger.info(f"[1] 적재 {total:,}건")
    for s in stats:
        logger.info(f"  {s['tier']:3s} {s['rows']:>7,}건 · 벤더 {_pct(s['vendor'], s['rows'])}"
                    f" · 공개일 {_pct(s['published'], s['rows'])}"
                    f" · 번역 {_pct(s['translated'], s['rows'])}"
                    f" · CVSS {_pct(s['cvss'], s['rows'])}")

    logger.info("[2] 알림 안전성")
    alerted = sum(s["alerted"] or 0 for s in stats)
    if alerted:
        blockers.append(f"시드가 알림을 보낸 흔적 {alerted:,}건 (last_alert_at 이 차 있다)")
        logger.error(f"  ❌ last_alert_at 이 있는 행 {alerted:,}건 — 시드는 알리지 않아야 한다")
    else:
        logger.info("  ✅ last_alert_at 전부 비어 있음 — 시드는 한 건도 알리지 않았다")

    for s in stats:
        if s["tier"] not in risk.ALERTING_TIERS:
            continue
        naked = s["rows"] - (s["fired"] or 0)
        if naked:
            blockers.append(f"{s['tier']} 중 발화 이력이 없는 행 {naked:,}건")
            logger.error(f"  ❌ {s['tier']} {naked:,}건에 fired_triggers 가 없다 — "
                         f"컷오버 첫 회차에 그대로 터진다")
        else:
            logger.info(f"  ✅ {s['tier']} {s['rows']:,}건 전부 발화 이력 선기록됨")

    logger.info("[3] 워터마크")
    watermark = pstate.read_watermark()
    if not watermark:
        blockers.append("워터마크가 없다")
        logger.error("  ❌ 없음 — fast-lane 이 어디부터 이어받을지 모른다")
    else:
        logger.info(f"  ✅ {watermark.isoformat()}")

    logger.info(f"[4] 소스 스냅샷 — 컷오버 첫 회차에 나갈 알림 (소스당 상한 {_CAP})")
    first_run = 0
    for key, source in signal_snapshot.SOURCES.items():
        known = db.get_snapshot_ids(key)
        if not known and source.catch_up is not None:
            # 재시드가 일부러 남겨 둔다 — bulk-lane 첫 회차가 최근 · 추적 안 된 것을 판정하며 기록한다(T2 근거).
            logger.info(f"  [{source.label}] 스냅샷 없음 — bulk-lane 첫 회차가 기록한다 (차단 아님)")
            continue
        if not known:
            blockers.append(f"{source.label} 스냅샷 없음")
            logger.error(f"  ❌ [{source.label}] 스냅샷 없음 — 첫 회차가 전량을 신규로 본다")
            continue
        upstream = source.load()
        if upstream is None:
            warnings.append(f"{source.label} 상류 수신 실패 — 대조 못 함")
            logger.warning(f"  ⚠️  [{source.label}] 상류 수신 실패 — 대조 건너뜀")
            continue
        added = set(upstream) - known
        capped = min(len(added), _CAP)
        first_run += capped
        logger.info(f"  [{source.label}] {'fast' if source.fast else 'bulk'} · "
                    f"기록 {len(known):,} · 상류 {len(upstream):,} · "
                    f"신규 {len(added):,}건 → 첫 회차 {capped}건")

    logger.info(f"  첫 회차 알림 예상 합계 {first_run:,}건")
    if first_run > 200:
        warnings.append(f"첫 회차 알림이 {first_run:,}건으로 많다")

    logger.info("[5] 누락 — 소스 후보 중 DB 에 없는 것")
    collector = Collector()
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    collector.ai_ledger = ai_provenance.load_anthropic_ledger()
    ids, _epss = seed_turso._candidates(collector)
    stored = set(db.get_tracked_ids())
    missing = [c for c in ids if c not in stored]
    if missing:
        warnings.append(f"후보 중 미적재 {len(missing):,}건")
        logger.warning(f"  ⚠️  {len(missing):,}/{len(ids):,}건 미적재 "
                       f"(cvelistV5 에 레코드가 없거나 T3 로 판정된 것들) — "
                       f"예: {', '.join(missing[:8])}")
    else:
        logger.info(f"  ✅ 후보 {len(ids):,}건 전부 적재됨")

    misses = len(db.get_pipeline_state().get(seed_turso._VENDOR_MISS_KEY) or [])
    vendor_left = total - sum(s["vendor"] or 0 for s in stats) - misses
    if vendor_left > 0:
        warnings.append(f"벤더 미보충 {vendor_left:,}건")
        logger.warning(f"[6] ⚠️  벤더 미보충 {vendor_left:,}건 — seed-turso 를 더 돌려야 한다")
    else:
        logger.info(f"[6] ✅ 벤더 보충 완료 (NVD 에도 없는 {misses:,}건 제외)")

    logger.info("=" * 60)
    if blockers:
        for b in blockers:
            logger.error(f"  차단: {b}")
        logger.error("컷오버 불가 — 위 항목을 먼저 해결하라")
        return 1
    for w in warnings:
        logger.warning(f"  주의: {w}")
    logger.info("컷오버 가능")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
