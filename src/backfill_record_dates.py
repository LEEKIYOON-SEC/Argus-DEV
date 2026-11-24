#!/usr/bin/env python3
"""추적 중인 행의 CVE 레코드 갱신 시각(record_updated)을 채운다 — 2026-11 에 받기 시작하기 전에 저장된 행.

레코드는 파이프라인과 같은 곳(cvelistV5)에서 받고, 상태의 그 키만 고친다(patch_states). updated_at 을 건드리지 않아
보존(90일) 기준과 증분 export 가 그대로다. 레코드에 갱신 시각이 없거나 레코드가 없으면 ''(확인했지만 없음)로 남겨
다시 받지 않고, 받지 못한 것은 비워 두어 다음 실행이 다시 받는다. 하나라도 채웠으면 다음 export 를 전량으로 요청한다 —
증분 export 는 updated_at 으로 고르므로 그대로면 화면에 반영되지 않는다.
시간 예산(BACKFILL_RECORD_BUDGET_S, 기본 40분) 안에서 최근에 저장된 행부터 하고, 남으면 다시 실행해 이어 간다.
"""
import os
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import feed
from fields import record_time
from logger import logger
from store import create_store

_CHUNK = 400
_KEY = "record_updated"


def plan(ids, records: dict, absent: set) -> tuple:
    """받은 레코드로 고칠 내용을 만든다 — (고칠 목록, 채운 수, 없음으로 둔 수, 못 받은 수)."""
    updates, filled, none, failed = [], 0, 0, 0
    for cve_id in ids:
        record = records.get(cve_id)
        if record is not None:
            when = record_time(((record or {}).get("cveMetadata") or {}).get("dateUpdated"))
            updates.append({"id": cve_id, "patch": {_KEY: when}})
            filled += 1 if when else 0
            none += 0 if when else 1
        elif cve_id in absent:
            updates.append({"id": cve_id, "patch": {_KEY: ""}})
            none += 1
        else:
            failed += 1
    return updates, filled, none, failed


def run(db, budget_s: float, fetch=feed.fetch_records, clock=time.monotonic) -> dict:
    ids = db.get_ids_missing_state_key(_KEY)
    total = {"targets": len(ids), "filled": 0, "none": 0, "failed": 0, "saved": 0, "left": 0}
    if not ids:
        logger.info("갱신 시각이 빠진 행이 없습니다 — 종료")
        return total
    logger.info(f"갱신 시각이 빠진 추적 행 {len(ids):,}건 (최근에 저장된 것부터, 예산 {budget_s / 60:.0f}분)")
    start = clock()
    done = 0
    for i in range(0, len(ids), _CHUNK):
        if clock() - start > budget_s:
            logger.info(f"⏰ 시간 예산 도달 — 남은 {len(ids) - i:,}건은 다시 실행하면 이어서 처리합니다")
            break
        chunk = ids[i:i + _CHUNK]
        records, absent = fetch(chunk)
        updates, filled, none, failed = plan(chunk, records, absent)
        # 덩어리마다 저장한다 — 끝에 한 번만 저장하면 시간 제한으로 작업이 끊길 때 전부 잃는다.
        total["saved"] += db.patch_states(updates, "레코드 갱신 시각") if updates else 0
        total["filled"] += filled
        total["none"] += none
        total["failed"] += failed
        done = i + len(chunk)
        logger.info(f"  {done:,}/{len(ids):,} — 채움 {total['filled']:,} · 출처에 없음 {total['none']:,} · "
                    f"못 받음 {total['failed']:,}")
    total["left"] = len(ids) - done + total["failed"]
    if total["saved"]:
        db.request_full_export()
    return total


def main() -> int:
    budget = float(os.environ.get("BACKFILL_RECORD_BUDGET_S", "2400"))
    logger.info("=" * 60)
    logger.info("CVE 레코드 갱신 시각 백필 시작")
    logger.info("=" * 60)
    total = run(create_store(), budget)
    logger.info("=" * 60)
    logger.info(f"백필 완료: 대상 {total['targets']:,} · 채움 {total['filled']:,} · 출처에 없음 {total['none']:,} · "
                f"저장 {total['saved']:,}건" + (" · 다음 export 는 전량" if total["saved"] else ""))
    if total["left"]:
        logger.info(f"남은 대상 {total['left']:,}건 — 다시 실행하면 이어서 처리합니다")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
