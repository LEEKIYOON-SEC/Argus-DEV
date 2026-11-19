from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Dict, List, Tuple

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import requests

import feed
import risk
from collector import collect_cvss, pick_cvss
from store import create_store
import nvd
from logger import logger

_VER = re.compile(r"CVSS:(\d\.\d)")
_LOG_SAMPLE = 30

_NVD_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))
_NVD_FAIL_STOP = 5


def version_of(vector) -> str:
    m = _VER.match(str(vector or "").strip())
    return m.group(1) if m else ""


def containers_of(record: Dict) -> List[Dict]:
    c = (record or {}).get("containers") or {}
    out = [c.get("cna") or {}]
    adp = c.get("adp")
    if isinstance(adp, list):
        out.extend(x for x in adp if isinstance(x, dict))
    return out


def nvd_cvss(cve_id: str, api_key: str = "", timeout: int = 60) -> Dict:
    try:
        resp = requests.get(nvd.ENDPOINT, params={"cveId": cve_id},
                            headers=nvd.headers(api_key), timeout=timeout)
        resp.raise_for_status()
        vulns = (resp.json() or {}).get("vulnerabilities") or []
    except (requests.exceptions.RequestException, ValueError) as e:
        raise RuntimeError(f"NVD 조회 실패: {e}") from e
    if not vulns:
        return {}

    metrics = ((vulns[0].get("cve") or {}).get("metrics") or {})
    found: Dict[str, Tuple[float, str]] = {}
    for key, label in _NVD_KEYS:
        for entry in metrics.get(key) or []:
            data = (entry or {}).get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            try:
                score = float(score)
            except (TypeError, ValueError):
                continue
            prev = found.get(label)
            if prev is None or prev[0] < score:
                found[label] = (score, data.get("vectorString") or "N/A")
    if found:
        return found

    for entry in metrics.get("cvssMetricV2") or []:
        data = (entry or {}).get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        try:
            score = float(score)
        except (TypeError, ValueError):
            continue
        prev = found.get("2.0")
        if prev is None or prev[0] < score:
            found["2.0"] = (score, data.get("vectorString") or "N/A")
    return found


def recompute(state: Dict, record: Dict) -> Dict:
    return apply_scores(state, collect_cvss(containers_of(record)))


def apply_scores(state: Dict, found: Dict) -> Dict:
    found = dict(found)
    old_score = float(state.get("cvss") or 0.0)
    old_vector = state.get("cvss_vector") or "N/A"
    old_ver = version_of(old_vector)

    if old_score > 0 and old_ver:
        prev = found.get(old_ver)
        if prev is None or float(prev[0]) < old_score:
            found[old_ver] = (old_score, old_vector)

    score, vector, ver = pick_cvss(found)
    if score < old_score:
        score, vector, ver = old_score, old_vector, old_ver

    new = dict(state)
    new["cvss"] = score
    new["cvss_vector"] = vector
    new["cvss_version"] = ver
    new["cvss_scores"] = {k: [v[0], v[1]] for k, v in found.items()}
    new["tier"] = risk.evaluate(new).tier
    return new


# recompute 가 바꾸는 키 — 저장할 때 이것만 쓴다(상태를 통째로 쓰면 그 사이 fast-lane 변경이 지워진다).
_CVSS_KEYS = ("cvss", "cvss_vector", "cvss_version", "cvss_scores", "tier")


def _priority(row: Dict) -> Tuple[int, int, str]:
    state = row.get("last_alert_state") or {}
    return (risk.tier_rank(str(state.get("tier") or risk.T3)),
            0 if float(state.get("cvss") or 0.0) <= 0.0 else 1,
            str(row.get("id") or ""))


def _fill_from_nvd(results: List[Tuple[str, Dict, Dict]],
                   budget: float) -> Tuple[int, int, int]:
    todo = [(cid, new) for cid, _, new in results if float(new.get("cvss") or 0.0) <= 0.0]
    if not todo:
        return 0, 0, 0

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    nvd.verify(api_key)
    gap = nvd.gap(api_key)
    logger.info(f"cvelistV5 에 점수가 없는 {len(todo):,}건 → NVD 조회 "
                f"(키 {'있음' if api_key else '없음'} · 건당 {gap}초 · "
                f"예상 {len(todo) * gap / 60:.0f}분 · 예산 {budget / 60:.0f}분)")

    started = time.time()
    fixed = v2_only = failed = streak = 0
    for i, (cve_id, new) in enumerate(todo):
        if time.time() - started > budget:
            logger.info(f"  시간 예산 소진 — {len(todo) - i:,}건은 다음 실행에서 이어서 본다")
            break
        try:
            found = nvd_cvss(cve_id, api_key)
            streak = 0
        except RuntimeError as e:
            failed += 1
            streak += 1
            logger.warning(f"  {cve_id} {e}")
            if streak >= _NVD_FAIL_STOP:
                logger.warning(f"  연속 {streak}회 실패 — NVD 조회를 중단한다 "
                               f"(레이트리밋일 가능성. 남은 {len(todo) - i - 1:,}건은 다음 실행)")
                break
            time.sleep(gap)
            continue

        if found:
            new.update(apply_scores(new, found))
            fixed += 1
            if set(found) == {"2.0"}:
                v2_only += 1
        if i < len(todo) - 1:
            time.sleep(gap)

    logger.info(f"NVD 보충 {fixed:,}/{len(todo):,}건 "
                f"(그중 CVSS 2.0 만 있는 것 {v2_only:,}건 — 버전을 함께 표기한다)"
                + (f" · 조회 실패 {failed:,}건" if failed else ""))
    return fixed, v2_only, failed


def run(limit: int, dry_run: bool, workers: int = 24, nvd_budget: float = 2400.0) -> int:
    started = time.time()
    db = create_store()

    rows = db.get_rows_needing_cvss()
    if not rows:
        logger.info("✅ 손볼 행이 없다 — 모두 버전이 있고 점수도 있다")
        return 0

    rows.sort(key=_priority)
    unscored = sum(1 for r in rows
                   if float((r.get("last_alert_state") or {}).get("cvss") or 0.0) <= 0.0)
    logger.info(f"대상 {len(rows):,}건 "
                f"(화면에 N/A 로 떠 있는 {unscored:,}건 먼저)")

    targets = rows[:limit]
    if len(rows) > limit:
        logger.info(f"이번 실행은 {limit:,}건까지만 — 나머지 {len(rows) - limit:,}건은 "
                    f"다시 돌리면 이어서 처리한다")

    changes = [feed.Change(cve_id=r["id"], batch_at=None) for r in targets if r.get("id")]
    feed.fill_records(changes, workers=workers)
    by_id = {c.cve_id: c.record for c in changes}

    results: List[Tuple[str, Dict, Dict]] = []
    no_record = 0

    for row in targets:
        cve_id = row.get("id")
        state = row.get("last_alert_state")
        record = by_id.get(cve_id)
        if not cve_id or not state:
            continue
        if record is None:
            no_record += 1
            continue
        try:
            results.append((cve_id, state, recompute(state, record)))
        except Exception as e:
            logger.warning(f"  {cve_id} 재계산 실패: {e}")

    nvd_fixed, nvd_v2, nvd_fail = _fill_from_nvd(results, nvd_budget)

    updates: List[Dict] = []
    raised, confirmed = 0, 0
    tier_moves: Dict[str, int] = {}
    for cve_id, state, new in results:
        old_score = float(state.get("cvss") or 0.0)
        if new["cvss"] > old_score:
            raised += 1
            if raised <= _LOG_SAMPLE:
                logger.info(f"  {cve_id} {old_score} → {new['cvss']} "
                            f"(v{new['cvss_version'] or '?'})")
            elif raised == _LOG_SAMPLE + 1:
                logger.info("  … 이하 생략 (상향 건수는 아래 요약에)")
        else:
            confirmed += 1

        before, after = str(state.get("tier") or risk.T3), new["tier"]
        if before != after:
            tier_moves[f"{before}→{after}"] = tier_moves.get(f"{before}→{after}", 0) + 1

        updates.append({
            "id": cve_id,
            "cvss_score": new["cvss"],
            "patch": {k: new[k] for k in _CVSS_KEYS},
        })

    if dry_run:
        ok = 0
    else:
        ok = db.patch_states(updates, "CVSS")
        if ok:
            db.request_full_export()

    still_na = sum(1 for _, _, new in results if float(new.get("cvss") or 0.0) <= 0.0)

    logger.info("=" * 60)
    logger.info(f"CVSS 소급{' 예행연습' if dry_run else ' 완료'}: 점수 상향 {raised:,} "
                f"(그중 NVD 보충 {nvd_fixed:,}) · 버전만 확인 {confirmed:,} · "
                + (f"저장 대상 {len(updates):,}건 (저장 안 함)" if dry_run
                   else f"저장 {ok:,}/{len(updates):,}건"))
    if nvd_v2:
        logger.info(f"  CVSS 2.0 으로 채운 것 {nvd_v2:,}건 — 3.x/4.0 이 어디에도 없는 옛 CVE 다. "
                    f"화면에 v2.0 이라고 함께 적힌다")
    if still_na:
        logger.warning(f"여전히 N/A {still_na:,}건 — cvelistV5 에도 NVD 에도 점수가 없다"
                       + (f" (조회 실패 {nvd_fail:,}건 포함, 다음 실행이 다시 본다)"
                          if nvd_fail else ""))
    if tier_moves:
        logger.info("등급 이동: " + " · ".join(f"{k} {v:,}" for k, v in sorted(tier_moves.items())))
        logger.info("  (점수를 찾으면 '점수 미부여 — 재평가 대기'(T2) 사유가 사라진다. "
                    "T3 로 내려가는 건 정상이다)")
    if no_record:
        logger.warning(f"레코드를 받지 못한 {no_record:,}건은 다음 실행에서 재시도")
    if len(rows) > len(targets):
        logger.info(f"남은 대상 {len(rows) - len(targets):,}건 — 다시 실행하면 이어서 처리")
    logger.info("Slack 알림 없음 · last_alert_at 미기록 — 이 도구는 notifier 를 부르지 않는다")
    logger.info(f"소요 {time.time() - started:.1f}초")
    logger.info("=" * 60)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="CVSS 가 낮거나 N/A 로 남은 행을 cvelistV5 재판독 + NVD 로 소급 보정")
    ap.add_argument("--limit", type=int,
                    default=int(os.environ.get("BACKFILL_CVSS_LIMIT", "1500")),
                    help="한 실행에서 처리할 최대 건수 (기본 1500)")
    ap.add_argument("--nvd-budget", type=float,
                    default=float(os.environ.get("BACKFILL_CVSS_NVD_BUDGET", "2400")),
                    help="NVD 조회에 쓸 최대 시간(초). 잡 타임아웃 60분 안에 들도록 "
                         "기본 2400초 — 넘으면 남은 건 다음 실행이 이어서 본다")
    ap.add_argument("--dry-run", action="store_true",
                    help="전부 계산만 하고 저장하지 않는다")
    args = ap.parse_args()
    try:
        return run(args.limit, args.dry_run, nvd_budget=args.nvd_budget)
    except Exception as e:
        logger.error(f"CVSS 소급 실패: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
