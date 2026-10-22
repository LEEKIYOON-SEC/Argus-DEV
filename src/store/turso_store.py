import datetime
import json
import os
import threading
from typing import Dict, List, Optional, Set, Tuple

import libsql

import turso_schema
from fields import meaningful
from logger import logger

from .base import Store, StoreError

_JSON_COLS = ("last_alert_state", "rules_snapshot")
_COLS = ("id", "cvss_score", "epss_score", "is_kev", "last_alert_state",
         "last_alert_at", "has_official_rules", "rules_snapshot",
         "last_rule_check_at", "updated_at")
_WRITE_CHUNK = 200


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _days_ago(days: int) -> str:
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=days)).isoformat()


def _has_vendor(state) -> int:
    if not isinstance(state, dict):
        return 0
    return int(any(meaningful(a.get("vendor"))
                   for a in (state.get("affected") or []) if isinstance(a, dict)))


class TursoStore(Store):

    def __init__(self, url: Optional[str] = None, auth_token: Optional[str] = None):
        url = (url if url is not None else os.environ.get("TURSO_DATABASE_URL", "")).strip()
        token = (auth_token if auth_token is not None
                 else os.environ.get("TURSO_AUTH_TOKEN", "")).strip()
        if not url:
            raise StoreError("TURSO_DATABASE_URL 이 설정되지 않음")
        self._lock = threading.Lock()
        try:
            self._conn = libsql.connect(database=url, auth_token=token)
        except Exception as e:
            raise StoreError(f"Turso 연결 실패: {e}") from e
        turso_schema.apply(self._conn)
        logger.info("Turso 연결 성공")

    def _query(self, sql: str, params=()) -> List[tuple]:
        try:
            with self._lock:
                return self._conn.execute(sql, params).fetchall()
        except Exception as e:
            raise StoreError(f"조회 실패: {e}") from e

    def _write(self, sql: str, params=()) -> int:
        try:
            with self._lock:
                cur = self._conn.execute(sql, params)
                self._conn.commit()
                return cur.rowcount
        except Exception as e:
            raise StoreError(f"저장 실패: {e}") from e

    @staticmethod
    def _row(values: tuple, cols=_COLS) -> Dict:
        out = dict(zip(cols, values))
        for key in _JSON_COLS:
            raw = out.get(key)
            if isinstance(raw, str) and raw:
                try:
                    out[key] = json.loads(raw)
                except ValueError:
                    out[key] = None
        if "is_kev" in out:
            out["is_kev"] = bool(out["is_kev"])
        if "has_official_rules" in out:
            out["has_official_rules"] = bool(out["has_official_rules"])
        return out

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        rows = self._query(f"SELECT {', '.join(_COLS)} FROM cves WHERE id = ?", (cve_id,))
        return self._row(rows[0]) if rows else None

    def get_cves(self, cve_ids) -> Tuple[Dict[str, Dict], Set[str]]:
        ids = [str(c) for c in cve_ids if c]
        rows: Dict[str, Dict] = {}
        covered: Set[str] = set()
        if not ids:
            return rows, covered
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            found = self._query(
                f"SELECT {', '.join(_COLS)} FROM cves WHERE id IN ({marks})", tuple(chunk))
            for values in found:
                row = self._row(values)
                rows[row["id"]] = row
            covered.update(chunk)
        return rows, covered

    @staticmethod
    def _params(data: Dict) -> Tuple[List[str], List]:
        cols, vals = [], []
        for key, value in data.items():
            if key not in _COLS:
                continue
            cols.append(key)
            if key in _JSON_COLS:
                vals.append(None if value is None
                            else json.dumps(value, ensure_ascii=False))
            elif key in ("is_kev", "has_official_rules"):
                vals.append(int(bool(value)))
            else:
                vals.append(value)
        if "last_alert_state" in data:
            cols.append("has_vendor")
            vals.append(_has_vendor(data.get("last_alert_state")))
        return cols, vals

    def _upsert_sql(self, data: Dict) -> Tuple[str, tuple]:
        cols, vals = self._params(data)
        if "id" not in cols:
            raise StoreError("upsert 에 id 가 없다")
        marks = ",".join("?" * len(cols))
        updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        sql = (f"INSERT INTO cves ({', '.join(cols)}) VALUES ({marks}) "
               f"ON CONFLICT(id) DO UPDATE SET {updates}")
        return sql, tuple(vals)

    def upsert_cve(self, data: Dict) -> bool:
        try:
            sql, params = self._upsert_sql(data)
            self._write(sql, params)
            return True
        except StoreError as e:
            logger.error(f"CVE 저장 실패 ({data.get('id')}): {e}")
            return False

    def bulk_save_states(self, updates: List[Dict], label: str = "상태") -> int:
        if not updates:
            return 0
        done = 0
        for i in range(0, len(updates), _WRITE_CHUNK):
            chunk = updates[i:i + _WRITE_CHUNK]
            try:
                with self._lock:
                    for item in chunk:
                        sql, params = self._upsert_sql(item)
                        self._conn.execute(sql, params)
                    self._conn.commit()
                done += len(chunk)
            except Exception as e:
                with self._lock:
                    self._conn.rollback()
                logger.warning(f"{label} 배치 저장 실패({len(chunk)}건): {e} → 행 단위 재시도")
                for item in chunk:
                    if self.upsert_cve(item):
                        done += 1
            logger.info(f"  {label} 저장 {min(i + len(chunk), len(updates)):,}/{len(updates):,}")
        return done

    def count_tracked(self) -> int:
        rows = self._query("SELECT count(*) FROM cves WHERE last_alert_state IS NOT NULL")
        return rows[0][0] if rows else 0

    def get_tracked_ids(self) -> List[str]:
        rows = self._query(
            "SELECT id FROM cves WHERE last_alert_state IS NOT NULL ORDER BY id")
        return [r[0] for r in rows]

    def get_rows_missing_vendor(self) -> List[Dict]:
        rows = self._query(
            "SELECT id, last_alert_state FROM cves "
            "WHERE last_alert_state IS NOT NULL AND has_vendor = 0 ORDER BY id")
        return [self._row(r, ("id", "last_alert_state")) for r in rows]

    def get_rows_needing_cvss(self) -> List[Dict]:
        rows = self._query(
            "SELECT id, last_alert_state FROM cves "
            "WHERE last_alert_state IS NOT NULL AND ("
            "  json_extract(last_alert_state, '$.cvss_version') IS NULL"
            "  OR coalesce(json_extract(last_alert_state, '$.cvss'), 0) <= 0"
            ") ORDER BY id")
        return [self._row(r, ("id", "last_alert_state")) for r in rows]

    def get_translation_backfill_candidates(self, limit: int = 60,
                                            offset: int = 0) -> List[Dict]:
        rows = self._query(
            "SELECT id, last_alert_state FROM cves WHERE last_alert_state IS NOT NULL "
            "ORDER BY id LIMIT ? OFFSET ?", (max(1, limit), max(0, offset)))
        return [self._row(r, ("id", "last_alert_state")) for r in rows]

    def update_translation(self, cve_id: str, title_ko: str, desc_ko: str) -> bool:
        try:
            n = self._write(
                "UPDATE cves SET last_alert_state = json_set("
                "  last_alert_state, '$.title_ko', ?, '$.desc_ko', ?) "
                "WHERE id = ? AND last_alert_state IS NOT NULL",
                (title_ko, desc_ko, cve_id))
            return n > 0
        except StoreError as e:
            logger.warning(f"{cve_id} 번역 갱신 실패: {e}")
            return False

    def get_missing_report_candidates(self, limit: int = 20) -> List[Dict]:
        cols = ("id", "cvss_score", "epss_score", "is_kev", "last_alert_state", "updated_at")
        rows = self._query(
            f"SELECT {', '.join(cols)} FROM cves "
            "WHERE last_alert_state IS NOT NULL AND has_analysis = 0 "
            "AND tier IN ('T0', 'T1') "
            "ORDER BY CASE tier WHEN 'T0' THEN 0 ELSE 1 END, "
            "  json_extract(last_alert_state, '$.is_kev_ransomware') DESC, "
            "  is_kev DESC, coalesce(published, '') DESC, cvss_score DESC "
            "LIMIT ?", (limit,))
        return [self._row(r, cols) for r in rows]

    def count_missing_reports(self) -> Dict[str, int]:
        rows = self._query(
            "SELECT tier, count(*) FROM cves "
            "WHERE last_alert_state IS NOT NULL AND has_analysis = 0 "
            "AND tier IN ('T0', 'T1') GROUP BY tier")
        return {t: n for t, n in rows}

    _RECHECK_COLS = ("id", "cvss_score", "epss_score", "is_kev",
                     "has_official_rules", "last_rule_check_at", "last_alert_at")

    def get_rule_recheck_candidates(self, limit: int = 10) -> List[Dict]:
        cutoff_7d = _days_ago(7)
        rows = self._query(
            f"SELECT {', '.join(self._RECHECK_COLS)} FROM cves WHERE "
            "  (last_rule_check_at IS NULL OR last_rule_check_at < ?) "
            "  AND has_official_rules = 0 "
            "  AND ("
            "        rules_snapshot IS NOT NULL"
            "     OR (rules_snapshot IS NULL AND cvss_score >= 7.0)"
            "  ) "
            "  AND ("
            "        is_kev = 1 OR epss_score > 0"
            "     OR (cvss_score >= 9.0 AND (last_alert_at IS NULL OR last_alert_at >= ?))"
            "     OR (cvss_score >= 7.0 AND cvss_score < 9.0"
            "         AND (last_alert_at IS NULL OR last_alert_at >= ?))"
            "  ) "
            "ORDER BY is_kev DESC, cvss_score DESC, epss_score DESC LIMIT ?",
            (cutoff_7d, _days_ago(180), _days_ago(90), limit))
        out = [self._row(r, self._RECHECK_COLS) for r in rows]
        logger.info(f"공개 룰 재확인 대상 {len(out)}건")
        return out

    _RULE_COLS = ("id", "cvss_score", "epss_score", "is_kev",
                  "has_official_rules", "rules_snapshot", "last_rule_check_at")

    def get_rule_rows(self, cve_ids, days: int = 90) -> Dict[str, Dict]:
        # 대시보드에 나오는 행(live_ids 와 같은 기준)만 — 룰 스냅샷을 색인과 견줘 빠진 룰을 찾는다(rule_refresh).
        ids = [str(c) for c in cve_ids if c]
        cutoff = _days_ago(days)
        rows: Dict[str, Dict] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            found = self._query(
                f"SELECT {', '.join(self._RULE_COLS)} FROM cves WHERE id IN ({marks}) "
                "AND last_alert_state IS NOT NULL AND updated_at >= ?", (*chunk, cutoff))
            for values in found:
                row = self._row(values, self._RULE_COLS)
                rows[row["id"]] = row
        return rows

    _STAT_COLS = ("tier", "rows", "alerted", "fired", "vendor",
                  "published", "translated", "cvss")

    def seed_stats(self) -> List[Dict]:
        rows = self._query(
            "SELECT coalesce(tier, '?'), count(*), "
            "  sum(last_alert_at IS NOT NULL), "
            "  sum(coalesce(json_array_length("
            "        json_extract(last_alert_state, '$.fired_triggers')), 0) > 0), "
            "  sum(has_vendor), "
            "  sum(published IS NOT NULL AND published != ''), "
            "  sum(coalesce(json_extract(last_alert_state, '$.title_ko'), '') != ''), "
            "  sum(cvss_score > 0) "
            "FROM cves WHERE last_alert_state IS NOT NULL "
            "GROUP BY 1 ORDER BY 1")
        return [dict(zip(self._STAT_COLS, r)) for r in rows]

    def get_pipeline_state(self) -> Dict:
        rows = self._query("SELECT key, value FROM pipeline_state")
        state = {}
        for key, value in rows:
            try:
                state[key] = json.loads(value) if value is not None else None
            except ValueError:
                state[key] = value
        return state

    def set_pipeline_state(self, state: Dict) -> bool:
        try:
            now = _now()
            with self._lock:
                for key, value in state.items():
                    if value is None:
                        self._conn.execute(
                            "DELETE FROM pipeline_state WHERE key = ?", (key,))
                        continue
                    self._conn.execute(
                        "INSERT INTO pipeline_state (key, value, updated_at) "
                        "VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value, updated_at=excluded.updated_at",
                        (key, json.dumps(value, ensure_ascii=False), now))
                self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"파이프라인 상태 저장 실패: {e}")
            return False

    def request_full_export(self) -> bool:
        return self.set_pipeline_state({"force_full_export": True})

    def take_full_export_flag(self) -> bool:
        rows = self._query("SELECT value FROM pipeline_state WHERE key = 'force_full_export'")
        if not rows or not rows[0][0] or rows[0][0] == "false":
            return False
        self._write("DELETE FROM pipeline_state WHERE key = 'force_full_export'")
        return True

    def get_snapshot_digest(self, source: str) -> Optional[str]:
        rows = self._query("SELECT digest FROM signal_snapshots WHERE source = ?", (source,))
        return rows[0][0] if rows else None

    def get_snapshot_ids(self, source: str) -> Set[str]:
        rows = self._query("SELECT cve_ids FROM signal_snapshots WHERE source = ?", (source,))
        if not rows:
            return set()
        try:
            ids = json.loads(rows[0][0])
        except ValueError as e:
            raise StoreError(f"스냅샷 집합 파싱 실패({source}): {e}") from e
        return {str(x) for x in ids} if isinstance(ids, list) else set()

    def save_snapshot(self, source: str, digest: str, ids) -> bool:
        try:
            self._write(
                "INSERT INTO signal_snapshots (source, digest, cve_ids, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(source) DO UPDATE SET "
                "digest=excluded.digest, cve_ids=excluded.cve_ids, "
                "updated_at=excluded.updated_at",
                (source, digest, json.dumps(sorted(ids)), _now()))
            return True
        except StoreError as e:
            logger.error(f"스냅샷 저장 실패({source}): {e}")
            return False

    _EXPORT_COLS = ("id", "cvss_score", "epss_score", "is_kev", "has_official_rules",
                    "last_alert_at", "last_alert_state", "rules_snapshot", "updated_at")

    def export_rows(self, since: Optional[str], days: int = 90) -> List[Dict]:
        cutoff = since or _days_ago(days)
        rows = self._query(
            f"SELECT {', '.join(self._EXPORT_COLS)} FROM cves "
            "WHERE last_alert_state IS NOT NULL AND updated_at >= ? ORDER BY id",
            (cutoff,))
        return [self._row(r, self._EXPORT_COLS) for r in rows]

    def live_ids(self, days: int = 90) -> Set[str]:
        rows = self._query(
            "SELECT id FROM cves WHERE last_alert_state IS NOT NULL AND updated_at >= ?",
            (_days_ago(days),))
        return {r[0] for r in rows}

    def count_rows(self, tracked: bool = False) -> int:
        sql = "SELECT count(*) FROM cves"
        if tracked:
            sql += " WHERE last_alert_state IS NOT NULL"
        rows = self._query(sql)
        return rows[0][0] if rows else 0

    _RETENTION_COLS = ("id", "is_kev", "cvss_score", "epss_score", "last_alert_state")

    def retention_rows(self, before: str, limit: int, *, tracked: bool = False,
                       unalerted: bool = False, oldest_first: bool = False
                       ) -> List[Dict]:
        clauses = ["updated_at < ?"]
        if tracked:
            clauses.append("last_alert_state IS NOT NULL")
        if unalerted:
            clauses.append("last_alert_at IS NULL")
        rows = self._query(
            f"SELECT {', '.join(self._RETENTION_COLS)} FROM cves "
            f"WHERE {' AND '.join(clauses)} "
            f"ORDER BY {'updated_at' if oldest_first else 'id'} LIMIT ?",
            (before, max(1, limit)))
        return [self._row(r, self._RETENTION_COLS) for r in rows]

    def delete_markers(self, before: str, limit: int) -> int:
        return self._write(
            "DELETE FROM cves WHERE id IN ("
            "  SELECT id FROM cves WHERE last_alert_state IS NULL "
            "  AND last_alert_at IS NULL AND updated_at < ? "
            "  ORDER BY updated_at LIMIT ?)",
            (before, max(1, limit)))

    def _by_ids(self, sql_head: str, ids) -> int:
        todo = [str(i) for i in ids if i]
        done = 0
        for i in range(0, len(todo), _WRITE_CHUNK):
            chunk = todo[i:i + _WRITE_CHUNK]
            marks = ",".join("?" * len(chunk))
            done += self._write(f"{sql_head} WHERE id IN ({marks})", tuple(chunk))
        return done

    def blank_states(self, ids) -> int:
        return self._by_ids(
            "UPDATE cves SET last_alert_state = NULL, rules_snapshot = NULL", ids)

    def delete_rows(self, ids) -> int:
        return self._by_ids("DELETE FROM cves", ids)
