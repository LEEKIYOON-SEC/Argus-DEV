import os
import sys
import time
from typing import Dict, List

import requests

from collector import affected_from_cpes
from store import create_store
import nvd
from logger import logger



_SAVE_EVERY = 50


def _fetch_cpe(cve_id: str, api_key: str, existing: List[Dict] = None) -> List[Dict]:
    headers = nvd.headers(api_key)
    try:
        r = requests.get(nvd.ENDPOINT, params={"cveId": cve_id}, headers=headers, timeout=60)
        r.raise_for_status()
        vulns = (r.json() or {}).get("vulnerabilities") or []
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.warning(f"  {cve_id} NVD 조회 실패: {e}")
        return []
    if not vulns:
        return []

    cpes = [m.get("criteria", "")
            for conf in (vulns[0].get("cve") or {}).get("configurations") or []
            for node in conf.get("nodes") or []
            for m in node.get("cpeMatch") or []]
    return affected_from_cpes(cpes, existing)


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    nvd.verify(api_key)
    limit = int(os.environ.get("BACKFILL_VENDOR_LIMIT", "500"))
    gap = nvd.gap(api_key)

    logger.info("=" * 60)
    logger.info(f"영향 벤더 백필 시작 (NVD 키 {'있음' if api_key else '없음'} · 건당 {gap}초)")
    logger.info("=" * 60)

    db = create_store()
    rows = db.get_rows_missing_vendor()
    if not rows:
        logger.info("벤더가 빠진 행이 없습니다 — 종료")
        return 0

    targets = rows[:limit]
    logger.info(f"대상 {len(rows):,}건 중 이번 실행 {len(targets):,}건 "
                f"(예상 {len(targets) * gap / 60:.0f}분)")

    updates, hit, miss, ok = [], 0, 0, 0
    for i, row in enumerate(targets, 1):
        cve_id = row.get("id")
        state = row.get("last_alert_state")
        if not cve_id or not state:
            continue
        affected = _fetch_cpe(cve_id, api_key, state.get("affected"))
        if affected:
            hit += 1
            # affected 키만 쓴다 — 몇십 분 전에 읽은 상태를 통째로 쓰면 그 사이의 변경이 지워진다.
            updates.append({"id": cve_id, "patch": {"affected": affected}})
            logger.info(f"  [{i}/{len(targets)}] {cve_id} → "
                        f"{affected[0]['vendor']} / {affected[0]['product']}")
        else:
            miss += 1
        if len(updates) >= _SAVE_EVERY:
            # 끝에 한 번만 저장하면 시간 제한으로 작업이 끊길 때 전부 잃는다.
            ok += db.patch_states(updates, "영향 벤더")
            updates = []
        if i < len(targets):
            time.sleep(gap)

    ok += db.patch_states(updates, "영향 벤더")
    if ok:
        db.request_full_export()
    logger.info("=" * 60)
    logger.info(f"벤더 백필 완료: 복구 {hit:,} · NVD에도 없음 {miss:,} · 저장 {ok:,}건")
    if len(rows) > len(targets):
        logger.info(f"남은 대상 {len(rows) - len(targets):,}건 — 다시 실행하면 이어서 처리합니다")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
