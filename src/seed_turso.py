import os
import re
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import ai_provenance
import enrichment_sources
import feed
import nvd
import pages
import pipeline
import risk
import signal_snapshot
import state as pstate
from collector import Collector
from fields import meaningful
from logger import logger
from store import create_store

T1_MIN_YEAR = int(os.environ.get("SEED_T1_MIN_YEAR", "2024"))
DEADLINE_MINUTES = int(os.environ.get("SEED_DEADLINE_MINUTES", "50"))
_YEAR = re.compile(r"CVE-(\d{4})-")
_VENDOR_MISS_KEY = "seed_vendor_misses"


class _Silent:
    def send_alert(self, *a, **k):
        raise AssertionError("시드는 알림을 보내지 않는다")

    def collect_alert(self, *a, **k):
        raise AssertionError("시드는 알림을 보내지 않는다")


def _year(cve_id: str) -> int:
    m = _YEAR.match(cve_id)
    return int(m.group(1)) if m else 0


def _candidates(collector: Collector):
    t0 = set(collector.kev_set) | set(collector.vulncheck_kev_set)
    t0 |= set(enrichment_sources.load_metasploit_index() or {})

    epss = enrichment_sources.load_epss_full() or {}
    t1 = set(enrichment_sources.load_nuclei_index() or {})
    t1 |= set(enrichment_sources.load_exploitdb_index() or {})
    t1 |= {c for c, (_s, p) in epss.items() if p >= risk.EPSS_P_CRITICAL}
    t1 |= set(ai_provenance.load_anthropic_ledger() or {})
    t1 -= t0
    t1 = {c for c in t1 if _year(c) >= T1_MIN_YEAR}

    logger.info(f"시드 후보: T0 {len(t0):,}건(전 연도) + "
                f"T1 {len(t1):,}건({T1_MIN_YEAR}년~) = {len(t0 | t1):,}건")
    return sorted(t0 | t1, reverse=True), epss


def _translations() -> dict:
    try:
        rows = pages.fetch_published_json("cves.json", timeout=180)
    except Exception as e:
        logger.warning(f"배포본을 읽지 못해 번역을 이어받지 못한다: {e}")
        return {}
    if not isinstance(rows, list):
        return {}
    out = {}
    for row in rows:
        cve_id = row.get("id")
        title = row.get("title") or ""
        desc = row.get("description") or ""
        if cve_id and (re.search(r"[가-힣]", title) or re.search(r"[가-힣]", desc)):
            out[cve_id] = (title, desc)
    logger.info(f"배포본에서 한글 번역 {len(out):,}건 확보")
    return out


def _fill_nvd(db, deadline: float, api_key: str):
    from collector import affected_from_cpes
    import requests

    known_misses = set(db.get_pipeline_state().get(_VENDOR_MISS_KEY) or [])
    rows = [r for r in db.get_rows_missing_vendor() if r["id"] not in known_misses]
    if not rows:
        logger.info(f"벤더 보충 대상 없음 (NVD 에도 없는 것으로 확인된 "
                    f"{len(known_misses):,}건 제외)")
        return 0, 0
    logger.info(f"NVD 벤더 보충 대상 {len(rows):,}건 · 이미 NVD 에도 없다고 확인된 "
                f"{len(known_misses):,}건은 건너뛴다 (남은 시간까지만)")
    gap = nvd.gap(api_key)
    done = 0
    asked = 0
    pending = []
    fresh_misses = set()
    for i, row in enumerate(rows):
        if time.time() > deadline:
            logger.warning(f"⏰ 예산 도달 — 벤더 보충 {i:,}/{len(rows):,}건 조회에서 중단 "
                           f"(다시 실행하면 이어서 처리한다)")
            break
        asked = i + 1
        cve_id = row["id"]
        try:
            r = requests.get(nvd.ENDPOINT, params={"cveId": cve_id},
                             headers=nvd.headers(api_key), timeout=60)
            if nvd.rejected_key(r):
                raise nvd.NvdKeyError("NVD_API_KEY 가 거부됐다")
            r.raise_for_status()
            vulns = (r.json() or {}).get("vulnerabilities") or []
        except nvd.NvdKeyError:
            raise
        except Exception as e:
            logger.debug(f"  {cve_id} NVD 조회 실패: {e}")
            time.sleep(gap)
            continue
        time.sleep(gap)
        cpes = [m.get("criteria", "")
                for conf in (vulns[0].get("cve") or {}).get("configurations") or []
                for node in conf.get("nodes") or []
                for m in node.get("cpeMatch") or []] if vulns else []
        state = dict(row.get("last_alert_state") or {})
        affected = affected_from_cpes(cpes, state.get("affected")) if cpes else []
        if not any(meaningful(a.get("vendor")) for a in affected):
            fresh_misses.add(cve_id)
            continue
        pending.append({"id": cve_id, "patch": {"affected": affected}})
        done += 1
        if len(pending) >= 200:
            db.patch_states(pending, "벤더")
            pending = []
    if pending:
        db.patch_states(pending, "벤더")
    if fresh_misses:
        db.set_pipeline_state(
            {_VENDOR_MISS_KEY: sorted(known_misses | fresh_misses)})
        logger.info(f"NVD 에도 벤더가 없는 {len(fresh_misses):,}건을 기록했다 "
                    f"(다음 실행에서 다시 묻지 않는다)")
    return done, len(rows) - asked


def run(dry_run: bool = False) -> int:
    started = time.time()
    deadline = started + DEADLINE_MINUTES * 60
    logger.info("=" * 60)
    logger.info(f"Turso 재시드 {'(드라이런)' if dry_run else ''}")
    logger.info("=" * 60)

    api_key = (os.environ.get("NVD_API_KEY") or "").strip()
    nvd.verify(api_key)

    db = create_store()
    pstate._DB_HANDLE = db
    resumed = pstate.read_watermark()
    if resumed:
        watermark = resumed
        logger.info(f"이어하기 — 워터마크는 첫 시드가 심은 {watermark.isoformat()} 를 "
                    f"그대로 둔다 (앞당기면 그 사이 변경이 통째로 사라진다)")
    else:
        batches = feed._fetch_delta_log(256 * 1024)
        stamps = [t for t in (feed._parse_ts(b.get("fetchTime")) for b in batches) if t]
        if not stamps:
            logger.error("deltaLog 를 읽지 못했다 — 워터마크를 정할 수 없어 중단한다")
            return 1
        watermark = max(stamps)
        logger.info(f"시드 기준 워터마크: {watermark.isoformat()} "
                    f"(이 시점 이후 변경은 첫 fast-lane 이 이어받는다)")

    collector = Collector()
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    collector.ai_ledger = ai_provenance.load_anthropic_ledger()
    ids, epss_index = _candidates(collector)

    stored = set(db.get_tracked_ids())
    todo = [c for c in ids if c not in stored]
    if stored:
        logger.info(f"이미 적재된 {len(stored):,}건은 건너뛴다 → 이번 판정 대상 {len(todo):,}건")

    if dry_run:
        logger.info("드라이런 — 여기서 멈춘다")
        return 0

    notifier = _Silent()
    carry = _translations() if todo else {}

    records = {}
    if todo:
        logger.info(f"cvelistV5 레코드 {len(todo):,}건 수신 중...")
        records, absent = feed.fetch_records(todo, workers=8)
        logger.info(f"레코드 확보 {len(records):,}건 · 없음 {len(absent):,}건")

    seeded = skipped = failed = 0
    judged = 0
    by_tier = {}
    chunk = 400
    for start in range(0, len(todo), chunk):
        if time.time() > deadline:
            logger.warning(f"⏰ 예산 도달 — {start:,}/{len(todo):,}건에서 중단")
            break
        window = [c for c in todo[start:start + chunk] if c in records]
        rows = pipeline.RowCache(db, window)
        for cve_id in window:
            try:
                st = pipeline.build_state(cve_id, records[cve_id], collector, epss_index)
            except Exception as e:
                logger.debug(f"{cve_id} 상태 구성 실패: {e}")
                failed += 1
                continue
            if st is None:
                skipped += 1
                continue
            tr = carry.get(cve_id)
            if tr:
                st["title_ko"], st["desc_ko"] = tr
            out = pipeline.process(st, db, notifier, rows=rows, silent=True)
            if out.status == "failed":
                failed += 1
            elif out.tier in risk.ALERTING_TIERS:
                seeded += 1
                by_tier[out.tier] = by_tier.get(out.tier, 0) + 1
            else:
                skipped += 1
        judged = min(start + chunk, len(todo))
        logger.info(f"  판정 {judged:,}/{len(todo):,} · 적재 {seeded:,}건")

    unjudged = len(todo) - judged
    logger.info(f"적재 {seeded:,}건 "
                f"({' · '.join(f'{t} {n:,}' for t, n in sorted(by_tier.items())) or '-'}) · "
                f"대상 아님 {skipped:,} · 실패 {failed:,}")

    pending_sources = [(k, s) for k, s in signal_snapshot.SOURCES.items()
                       if db.get_snapshot_digest(k) is None]
    logger.info(f"소스 스냅샷: {len(signal_snapshot.SOURCES) - len(pending_sources)}"
                f"/{len(signal_snapshot.SOURCES)}종은 이미 기록돼 있어 손대지 않는다 "
                f"(덮으면 그 사이 올라온 신규가 조용히 삼켜진다)")
    for key, source in pending_sources:
        upstream = source.load()
        if upstream is None:
            logger.warning(f"  [{source.label}] 수신 실패 — 스냅샷을 남기지 않는다 "
                           f"(다음 실행이 이어받는다)")
            continue
        db.save_snapshot(key, signal_snapshot.digest_of(upstream), upstream)
        logger.info(f"  [{source.label}] 스냅샷 {len(upstream):,}건 기록")

    filled, remaining_vendor = _fill_nvd(db, deadline, api_key)
    logger.info(f"NVD 벤더 보충 {filled:,}건")

    if not resumed:
        pstate.write_watermark(watermark)
        logger.info(f"워터마크 심음: {watermark.isoformat()}")
    db.request_full_export()

    total = db.count_tracked()
    logger.info("=" * 60)
    logger.info(f"{(time.time() - started) / 60:.1f}분 · 누적 적재 {total:,}건")
    if unjudged or remaining_vendor:
        logger.warning(f"미완: 미판정 {unjudged:,}건 · 벤더 미보충 {remaining_vendor:,}건 "
                       f"— seed-turso 를 다시 실행하면 이 지점부터 이어간다")
    else:
        logger.info("재시드 완료 — 더 실행할 것이 없다")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run(dry_run="--dry-run" in sys.argv))
