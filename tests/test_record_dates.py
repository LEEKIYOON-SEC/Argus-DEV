"""CVE 레코드 갱신 시각 — 수집(record_updated) · 저장 · 화면 시각(date) · 기존 행 백필 (INVARIANTS §6 '2차 개선')"""
import datetime as dt
import os
import sqlite3
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

if "libsql" not in sys.modules:
    _stub = types.ModuleType("libsql")
    _stub.connect = lambda database=None, auth_token=None: sqlite3.connect(":memory:", check_same_thread=False)
    sys.modules["libsql"] = _stub

import backfill_record_dates as brd  # noqa: E402
import export_dashboard_data as ex  # noqa: E402
import pipeline  # noqa: E402
from collector import Collector  # noqa: E402
from fields import record_time  # noqa: E402
from store.base import StoreError  # noqa: E402
from store.turso_store import TursoStore  # noqa: E402


def record(**meta):
    base = {"cveId": "CVE-2026-0001", "state": "PUBLISHED", "datePublished": "2026-11-20T10:00:00.000Z",
            "dateUpdated": "2026-11-23T14:05:12.432Z"}
    base.update(meta)
    return {"cveMetadata": base, "containers": {"cna": {"title": "Acme Widget RCE",
                                                         "descriptions": [{"lang": "en", "value": "x"}]}}}


class RecordTimeTests(unittest.TestCase):
    def test_normalised_to_utc_seconds(self):
        self.assertEqual(record_time("2026-11-23T14:05:12.432Z"), "2026-11-23T14:05:12Z")
        self.assertEqual(record_time("2026-11-23T23:05:12+09:00"), "2026-11-23T14:05:12Z")
        self.assertEqual(record_time("2026-11-23T14:05:12"), "2026-11-23T14:05:12Z", "시간대가 없으면 UTC (CVE JSON 5)")
        self.assertEqual(record_time("2026-11-23T14:05:12.4321234Z"), "2026-11-23T14:05:12Z", "소수점 일곱 자리")
        for bad in ("", None, "garbage", "2026-13-40"):
            self.assertEqual(record_time(bad), "", repr(bad))

    def test_parse_record_keeps_the_record_update_time(self):
        data = Collector().parse_record("CVE-2026-0001", record())
        self.assertEqual(data["published"], "2026-11-20")
        self.assertEqual(data["record_updated"], "2026-11-23T14:05:12Z")
        self.assertEqual(Collector().parse_record("CVE-2026-0001", record(dateUpdated=None))["record_updated"], "",
                         "출처에 없으면 비워 둔다 (공개일로 채우지 않는다)")

    def test_saved_with_the_state(self):
        self.assertIn("record_updated", pipeline.STATE_FIELDS)
        saved = []

        class DB:
            def upsert_cve(self, payload):
                saved.append(payload)
                return True

        state = {"id": "CVE-2026-0001", "record_updated": "2026-11-23T14:05:12Z", "has_poc": True}
        decision = pipeline.risk.decide(state, None)
        self.assertTrue(pipeline._save(DB(), state, decision, None, alerted=False))
        self.assertEqual(saved[0]["last_alert_state"]["record_updated"], "2026-11-23T14:05:12Z")


class EventTimeTests(unittest.TestCase):
    def test_latest_of_alert_and_record_update_in_kst(self):
        self.assertEqual(ex.event_time("2026-11-24T10:59:51.357507+09:00", "2026-11-23T14:05:12Z"),
                         "2026-11-24T10:59:51.357507+09:00", "알림이 더 늦다")
        self.assertEqual(ex.event_time("2026-11-20T09:00:00+09:00", "2026-11-23T14:05:12Z"),
                         "2026-11-23T23:05:12+09:00", "레코드 갱신이 더 늦다 — KST 로")
        self.assertEqual(ex.event_time("", "2026-11-23T14:05:12Z"), "2026-11-23T23:05:12+09:00", "알림을 보낸 적 없음")

    def test_published_when_nothing_else_and_never_the_save_time(self):
        self.assertEqual(ex.event_time(None, "", "2026-09-01"), "2026-09-01T09:00:00+09:00", "갱신 시각을 받기 전 행")
        self.assertEqual(ex.event_time("garbage", "", ""), "")
        self.assertEqual(ex.event_time("", "", ""), "")


class FakeExportDB:
    def __init__(self, rows):
        self.rows = rows

    def export_rows(self, since, days=90):
        return list(self.rows)


class ExportFieldTests(unittest.TestCase):
    def _row(self, **over):
        now = dt.datetime.now(dt.timezone.utc)
        base = {"id": "CVE-2010-20111", "cvss_score": 9.8, "epss_score": 0.2, "is_kev": False,
                "last_alert_at": None, "updated_at": now.isoformat(), "rules_snapshot": {},
                "has_official_rules": False,
                "last_alert_state": {"title": "x", "published": "2010-05-01", "tier": "T2",
                                     "record_updated": "2024-06-04T17:25:49Z"}}
        base.update(over)
        return base

    def test_maintenance_save_does_not_make_an_old_cve_recent(self):
        # 룰 재확인 같은 정비 작업이 방금 다시 저장한 옛 CVE — 예전에는 date 가 방금 시각이라 24시간 · 목록 맨 위에 섞였다
        (entry,) = ex.export_cves(FakeExportDB([self._row()]))
        self.assertEqual(entry["date"], "2024-06-05T02:25:49+09:00")
        self.assertEqual(entry["record_updated"], "2024-06-04T17:25:49Z")
        self.assertEqual(entry["alerted"], "")
        self.assertTrue(entry["updated"], "병합 · 보존 기준은 그대로 싣는다")
        self.assertEqual(ex.export_stats([entry])["cve"]["recent_24h"], 0)

    def test_alert_and_record_update_count_as_recent(self):
        now = dt.datetime.now(dt.timezone(dt.timedelta(hours=9)))
        alerted = self._row(last_alert_at=now.isoformat())
        fresh = self._row(id="CVE-2026-0002")
        fresh["last_alert_state"] = dict(fresh["last_alert_state"], record_updated=record_time(now.isoformat()))
        entries = ex.export_cves(FakeExportDB([alerted, fresh]))
        self.assertEqual(entries[0]["alerted"], now.isoformat())
        self.assertEqual(ex.export_stats(entries)["cve"]["recent_24h"], 2)

    def test_schema_bumped_for_the_new_fields(self):
        self.assertEqual(ex.export_stats([])["schema"], 5)


class StoreQueryTests(unittest.TestCase):
    def setUp(self):
        self.db = TursoStore(url="libsql://test", auth_token="t")
        rows = [("CVE-2026-0001", "2026-11-01T00:00:00+09:00", {"id": "a"}),
                ("CVE-2026-0002", "2026-11-03T00:00:00+09:00", {"id": "b"}),
                ("CVE-2026-0003", "2026-11-02T00:00:00+09:00", {"id": "c", "record_updated": ""}),
                ("CVE-2026-0004", "2026-11-04T00:00:00+09:00", {"id": "d", "record_updated": "2026-11-01T00:00:00Z"})]
        for cve_id, updated, state in rows:
            self.db.upsert_cve({"id": cve_id, "updated_at": updated, "last_alert_state": state})
        self.db.upsert_cve({"id": "CVE-2026-0005", "updated_at": "2026-11-05T00:00:00+09:00"})

    def test_missing_key_only_newest_first(self):
        self.assertEqual(self.db.get_ids_missing_state_key("record_updated"), ["CVE-2026-0002", "CVE-2026-0001"],
                         "'' 은 확인했지만 출처에 없음 — 다시 받지 않는다. 상태 없는 행도 넣지 않는다")
        with self.assertRaises(StoreError):
            self.db.get_ids_missing_state_key("bad key')--")

    def test_backfill_patch_keeps_the_save_time(self):
        self.db.patch_states([{"id": "CVE-2026-0001", "patch": {"record_updated": "2026-10-01T00:00:00Z"}}])
        row = self.db.get_cve("CVE-2026-0001")
        self.assertEqual(row["last_alert_state"], {"id": "a", "record_updated": "2026-10-01T00:00:00Z"})
        self.assertEqual(row["updated_at"], "2026-11-01T00:00:00+09:00", "보존 · 증분 export 기준을 바꾸지 않는다")


class FakeBackfillDB:
    def __init__(self, ids):
        self.ids = ids
        self.patched = []
        self.full = 0

    def get_ids_missing_state_key(self, key):
        assert key == "record_updated"
        return list(self.ids)

    def patch_states(self, updates, label=""):
        self.patched.extend(updates)
        return len(updates)

    def request_full_export(self):
        self.full += 1
        return True


class BackfillTests(unittest.TestCase):
    def test_fills_marks_missing_and_leaves_failures_for_the_next_run(self):
        recs = {"CVE-A": record(dateUpdated="2026-11-23T14:05:12Z"), "CVE-B": record(dateUpdated=None)}
        db = FakeBackfillDB(["CVE-A", "CVE-B", "CVE-C", "CVE-D"])
        total = brd.run(db, 60, fetch=lambda ids: ({k: v for k, v in recs.items() if k in ids}, {"CVE-C"} & set(ids)))
        self.assertEqual(db.patched, [{"id": "CVE-A", "patch": {"record_updated": "2026-11-23T14:05:12Z"}},
                                      {"id": "CVE-B", "patch": {"record_updated": ""}},
                                      {"id": "CVE-C", "patch": {"record_updated": ""}}],
                         "레코드에 갱신 시각이 없거나(B) 레코드가 없으면(C) '' · 못 받은 것(D)은 손대지 않는다")
        self.assertEqual((total["filled"], total["none"], total["failed"], total["left"]), (1, 2, 1, 1))
        self.assertEqual(db.full, 1, "고친 것이 있으면 다음 export 는 전량")

    def test_time_budget_and_nothing_to_do(self):
        ticks = iter([0, 0, 100, 100])
        db = FakeBackfillDB([f"CVE-{n}" for n in range(brd._CHUNK + 5)])
        total = brd.run(db, 50, fetch=lambda ids: ({}, set(ids)), clock=lambda: next(ticks))
        self.assertEqual(len(db.patched), brd._CHUNK, "첫 덩어리만 하고 예산에서 멈춘다")
        self.assertEqual(total["left"], 5)
        empty = FakeBackfillDB([])
        self.assertEqual(brd.run(empty, 60, fetch=lambda ids: self.fail("받지 않는다"))["targets"], 0)
        self.assertEqual(empty.full, 0)


if __name__ == "__main__":
    unittest.main()
