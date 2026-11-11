from __future__ import annotations

import datetime
import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import pytz
import requests

from logger import logger

_RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
_DELTA_LOG = f"{_RAW_BASE}/cves/deltaLog.json"
_RELEASE_BASE = "https://github.com/CVEProject/cvelistV5/releases/download"
_UA = {"User-Agent": "argus-feed"}

_RANGE_STEPS: Tuple[Optional[int], ...] = (256 * 1024, 1024 * 1024, 4 * 1024 * 1024, None)

BULK_PREFILL_HOURS = 3
PREFILL_MIN_CHANGES = 120
CATCHUP_MAX_HOURS = 24
BOOTSTRAP_HOURS = 2
DELTA_LOG_RETENTION_DAYS = 30

_TIMEOUT = 90


@dataclass
class Change:
    cve_id: str
    batch_at: datetime.datetime
    record: Optional[dict] = field(default=None, repr=False)


def _utc(dt: datetime.datetime) -> datetime.datetime:
    return dt.astimezone(pytz.UTC) if dt.tzinfo else pytz.UTC.localize(dt)


def _parse_ts(value) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _parse_array_prefix(text: str) -> List[dict]:
    decoder = json.JSONDecoder()
    idx = text.find("[")
    if idx < 0:
        return []
    idx += 1
    out: List[dict] = []
    n = len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n,":
            idx += 1
        if idx >= n or text[idx] == "]":
            break
        try:
            obj, idx = decoder.raw_decode(text, idx)
        except ValueError:
            break
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _fetch_delta_log(nbytes: Optional[int]) -> List[dict]:
    headers = dict(_UA)
    if nbytes is not None:
        headers["Range"] = f"bytes=0-{nbytes - 1}"
    resp = requests.get(_DELTA_LOG, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    return _parse_array_prefix(resp.content.decode("utf-8", errors="ignore"))


def _load_batches(since: datetime.datetime) -> Tuple[List[dict], bool]:
    for step in _RANGE_STEPS:
        label = "전량" if step is None else f"{step // 1024}KB"
        try:
            batches = _fetch_delta_log(step)
        except requests.exceptions.RequestException as e:
            logger.warning(f"deltaLog {label} 수신 실패: {e}")
            continue
        stamps = [t for t in (_parse_ts(b.get("fetchTime")) for b in batches) if t]
        if not stamps:
            continue
        if min(stamps) <= since or step is None:
            covered = min(stamps) <= since
            logger.info(f"📥 deltaLog {label} · 배치 {len(batches)}건"
                        f"{'' if covered else ' (구간 미달)'}")
            return batches, covered
        logger.debug(f"deltaLog {label}로는 부족 (가장 오래된 배치 {min(stamps).isoformat()})")
    return [], False


def _collect(batches: List[dict], since: datetime.datetime,
             until: datetime.datetime) -> Tuple[List[Change], datetime.datetime]:
    latest: Dict[str, Change] = {}
    horizon = since
    for batch in batches:
        batch_at = _parse_ts(batch.get("fetchTime"))
        if batch_at is None or batch_at <= since or batch_at > until:
            continue
        if batch_at > horizon:
            horizon = batch_at
        for key in ("new", "updated"):
            for item in batch.get(key) or []:
                cve_id = item.get("cveId")
                if not cve_id:
                    continue
                prev = latest.get(cve_id)
                if prev is not None and prev.batch_at >= batch_at:
                    continue
                latest[cve_id] = Change(cve_id=cve_id, batch_at=batch_at)
    changes = sorted(latest.values(), key=lambda c: c.batch_at)
    return changes, horizon


def _fetch_day_zip(day: datetime.date, newest_hour: int = 23) -> Dict[str, dict]:
    for hour in range(newest_hour, -1, -1):
        tag = f"cve_{day:%Y-%m-%d}_{hour:02d}00Z"
        asset = f"{day:%Y-%m-%d}_delta_CVEs_at_{hour:02d}00Z.zip"
        try:
            resp = requests.get(f"{_RELEASE_BASE}/{tag}/{asset}",
                                timeout=_TIMEOUT, headers=_UA)
        except requests.exceptions.RequestException as e:
            logger.debug(f"delta ZIP {tag} 수신 실패: {e}")
            continue
        if resp.status_code != 200 or len(resp.content) < 100:
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                out: Dict[str, dict] = {}
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        record = json.loads(zf.read(name))
                    except ValueError:
                        continue
                    cve_id = (record.get("cveMetadata") or {}).get("cveId")
                    if cve_id:
                        out[cve_id] = record
            logger.info(f"📦 delta ZIP {day:%Y-%m-%d} {hour:02d}Z → 레코드 {len(out)}건")
            return out
        except zipfile.BadZipFile as e:
            logger.warning(f"delta ZIP {tag} 해제 실패: {e}")
    return {}


def prefill_records(changes: List[Change], since: datetime.datetime,
                    until: datetime.datetime,
                    deadline: Optional[float] = None) -> int:
    if not changes:
        return 0
    span_h = (until - since).total_seconds() / 3600.0
    if span_h < BULK_PREFILL_HOURS and len(changes) < PREFILL_MIN_CHANGES:
        return 0

    pool: Dict[str, dict] = {}
    day = since.date()
    while day <= until.date():
        if deadline is not None and time.time() > deadline:
            logger.warning("⏰ ZIP 선충전 도중 시간 예산 도달 — 나머지는 개별 요청으로")
            break
        newest = until.hour if day == until.date() else 23
        pool.update(_fetch_day_zip(day, newest_hour=newest))
        day += datetime.timedelta(days=1)

    filled = 0
    for change in changes:
        if change.record is None and change.cve_id in pool:
            change.record = pool[change.cve_id]
            filled += 1
    if filled:
        logger.info(f"📦 ZIP으로 레코드 {filled}/{len(changes)}건 선충전 "
                    f"(개별 요청 그만큼 절약)")
    return filled


def changes_since(since: Optional[datetime.datetime],
                  now: Optional[datetime.datetime] = None,
                  prefill: bool = True,
                  deadline: Optional[float] = None,
                  cap: Optional[int] = None) -> Tuple[List[Change], datetime.datetime]:
    now = _utc(now or datetime.datetime.now(pytz.UTC))
    if since is None:
        since = now - datetime.timedelta(hours=BOOTSTRAP_HOURS)
        logger.info(f"워터마크 없음 → 최근 {BOOTSTRAP_HOURS}h 부트스트랩")
    since = _utc(since)
    if since >= now:
        return [], now

    retention_floor = now - datetime.timedelta(days=DELTA_LOG_RETENTION_DAYS)
    if since < retention_floor:
        logger.error(f"⛔ 워터마크({since.isoformat()})가 deltaLog 보관기간"
                     f"({DELTA_LOG_RETENTION_DAYS}일) 밖 — {retention_floor.isoformat()}부터 재개")
        since = retention_floor

    until = min(now, since + datetime.timedelta(hours=CATCHUP_MAX_HOURS))
    if until < now:
        logger.warning(f"공백 {(now - since).total_seconds() / 3600:.1f}h — 이번 실행은 "
                       f"{CATCHUP_MAX_HOURS}h까지만 따라잡는다 (나머지는 다음 실행)")

    batches, covered = _load_batches(since)
    if not batches:
        logger.warning("deltaLog를 읽지 못함 — 이번 실행은 워터마크를 전진시키지 않는다")
        return [], since
    if not covered:
        logger.error("⛔ deltaLog 전량으로도 구간을 못 덮음 — 그 앞 구간은 유실 가능")

    changes, horizon = _collect(batches, since, until)
    if covered and until < now and horizon < until:
        # 따라잡기 구간(24h)을 다 봤는데 그 끝까지 배치가 없었다 — 구간 끝으로 옮기지 않으면 같은 구간만 되풀이한다.
        horizon = until
    logger.info(f"변경 CVE {len(changes)}건 ({since:%m-%d %H:%M} → {horizon:%m-%d %H:%M} UTC)")
    if cap is not None:
        changes, horizon = cap_by_batch(changes, cap, horizon)
    if prefill:
        prefill_records(changes, since, until, deadline=deadline)
    return changes, horizon


def cap_by_batch(changes: List[Change], cap: int, horizon: datetime.datetime
                 ) -> Tuple[List[Change], datetime.datetime]:
    if len(changes) <= cap:
        return changes, horizon

    kept: List[Change] = []
    cut_at = None
    for change in changes:
        if change.batch_at != cut_at:
            if len(kept) >= cap:
                break
            cut_at = change.batch_at
        kept.append(change)

    if len(kept) > cap:
        logger.warning(f"단일 배치가 {len(kept)}건 — 상한 {cap}을 넘지만 쪼개면 유실되므로 "
                       f"통째로 처리한다 (초과분은 시간 데드라인이 받는다)")

    logger.warning(f"변경 {len(changes)}건 > 상한 {cap} — 배치 경계에서 잘라 {len(kept)}건만 "
                   f"이번 회차에 처리 (나머지 {len(changes) - len(kept)}건은 다음 회차)")
    return kept, cut_at


def _fetch(cve_id: str, timeout: int = 20) -> Tuple[Optional[dict], bool]:
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None, True
    year, num = parts[1], parts[2]
    group = "0xxx" if len(num) < 4 else num[:-3] + "xxx"
    url = f"{_RAW_BASE}/cves/{year}/{group}/{cve_id}.json"
    try:
        resp = requests.get(url, timeout=timeout, headers=_UA)
        if resp.status_code == 404:
            logger.warning(f"{cve_id}: 레코드 없음 (404)")
            return None, True
        resp.raise_for_status()
        return resp.json(), False
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.debug(f"{cve_id} 레코드 수신 실패: {e}")
        return None, False


def fetch_records(cve_ids: List[str], workers: int = 8
                  ) -> Tuple[Dict[str, dict], Set[str]]:
    ids = list(dict.fromkeys(cve_ids))
    if not ids:
        return {}, set()
    records: Dict[str, dict] = {}
    absent: Set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for cve_id, (record, gone) in zip(ids, ex.map(_fetch, ids)):
            if record is not None:
                records[cve_id] = record
            elif gone:
                absent.add(cve_id)
    failed = len(ids) - len(records) - len(absent)
    logger.info(f"레코드 일괄 수신 {len(records)}/{len(ids)}건"
                + (f" · 없음 {len(absent)}건" if absent else "")
                + (f" · 실패 {failed}건은 다음 실행 재시도" if failed else ""))
    return records, absent


def fill_records(changes: List[Change], workers: int = 8) -> List[Change]:
    pending = [c for c in changes if c.record is None]
    if not pending:
        return changes
    records, _absent = fetch_records([c.cve_id for c in pending], workers=workers)
    for change in pending:
        change.record = records.get(change.cve_id)
    return changes
