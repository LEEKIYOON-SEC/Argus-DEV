"""상태의 일부 키만 바꾸는 저장 — 백필이 그 사이 fast-lane 변경을 덮지 않는다 (INVARIANTS §5)"""
import os
import sqlite3
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

# libsql 은 SQLite 호환이다 — 테스트는 메모리 SQLite 로 같은 SQL 을 돌린다.
if "libsql" not in sys.modules:
    _stub = types.ModuleType("libsql")
    _stub.connect = lambda database=None, auth_token=None: sqlite3.connect(":memory:", check_same_thread=False)
    sys.modules["libsql"] = _stub

from store.turso_store import TursoStore  # noqa: E402
from store.base import StoreError  # noqa: E402


class PatchStatesTests(unittest.TestCase):
    def setUp(self):
        self.db = TursoStore(url="libsql://test", auth_token="t")
        self.db.upsert_cve({"id": "CVE-2026-0001", "cvss_score": 0.0, "updated_at": "2026-11-01T00:00:00+09:00",
                            "last_alert_state": {"id": "CVE-2026-0001", "tier": "T1", "title": "제목 'x'",
                                                 "fired_triggers": ["kev"], "affected": []}})
        self.db.upsert_cve({"id": "CVE-2026-0002", "updated_at": "2026-11-01T00:00:00+09:00"})  # 상태 없는 표식 행

    def state(self, cve_id="CVE-2026-0001"):
        return self.db.get_cve(cve_id)

    def test_only_the_patched_keys_change(self):
        # 백필이 상태를 읽은 뒤 fast-lane 이 발화 이력을 늘렸다
        self.db.upsert_cve({"id": "CVE-2026-0001", "updated_at": "2026-11-02T00:00:00+09:00",
                            "last_alert_state": {"id": "CVE-2026-0001", "tier": "T0", "title": "제목 'x'",
                                                 "fired_triggers": ["kev", "msf"], "affected": []}})
        n = self.db.patch_states([{"id": "CVE-2026-0001", "patch": {"analysis": {"summary": "요약 \"따옴표\"", "n": 1}}}])
        row = self.state()
        self.assertEqual(n, 1)
        self.assertEqual(row["last_alert_state"]["analysis"], {"summary": "요약 \"따옴표\"", "n": 1})
        self.assertEqual(row["last_alert_state"]["fired_triggers"], ["kev", "msf"], "그 사이의 변경이 남는다")
        self.assertEqual(row["last_alert_state"]["tier"], "T0")
        self.assertEqual(row["updated_at"], "2026-11-02T00:00:00+09:00")

    def test_affected_patch_updates_the_vendor_flag(self):
        self.assertEqual(len(self.db.get_rows_missing_vendor()), 1)
        self.db.patch_states([{"id": "CVE-2026-0001",
                               "patch": {"affected": [{"vendor": "Acme", "product": "Widget", "versions": ""}]}}])
        self.assertEqual(self.db.get_rows_missing_vendor(), [])
        self.assertEqual(self.state()["last_alert_state"]["affected"][0]["vendor"], "Acme")

    def test_extra_columns_and_scalar_values(self):
        self.db.patch_states([{"id": "CVE-2026-0001", "cvss_score": 9.8, "has_official_rules": True,
                               "rules_snapshot": {"sigma": None, "network": []},
                               "patch": {"cvss": 9.8, "cvss_version": "3.1", "cvss_vector": None, "tier": "T0"}}])
        row = self.state()
        self.assertEqual((row["cvss_score"], row["has_official_rules"]), (9.8, True))
        self.assertEqual(row["rules_snapshot"], {"sigma": None, "network": []})
        st = row["last_alert_state"]
        self.assertEqual((st["cvss"], st["cvss_version"], st["cvss_vector"], st["tier"]), (9.8, "3.1", None, "T0"))

    def test_rows_without_state_or_unknown_ids_are_not_created(self):
        n = self.db.patch_states([{"id": "CVE-2026-0002", "patch": {"analysis": {}}},
                                  {"id": "CVE-2026-9999", "patch": {"analysis": {}}}])
        self.assertEqual(n, 0)
        self.assertIsNone(self.state("CVE-2026-0002")["last_alert_state"])
        self.assertIsNone(self.state("CVE-2026-9999"))

    def test_bad_key_is_refused_and_good_rows_still_save(self):
        with self.assertRaises(StoreError):
            self.db._patch_sql({"id": "CVE-2026-0001", "patch": {"a') , x = ('": 1}})
        n = self.db.patch_states([{"id": "CVE-2026-0001", "patch": {"bad key": 1}},
                                  {"id": "CVE-2026-0001", "patch": {"analysis": {"ok": True}}}])
        self.assertEqual(n, 1)
        self.assertEqual(self.state()["last_alert_state"]["analysis"], {"ok": True})


class FullExportFlagTests(unittest.TestCase):
    def test_peek_does_not_clear(self):
        db = TursoStore(url="libsql://test", auth_token="t")
        self.assertFalse(db.has_full_export_flag())
        db.request_full_export()
        self.assertTrue(db.has_full_export_flag())
        self.assertTrue(db.has_full_export_flag())
        db.clear_full_export_flag()
        self.assertFalse(db.has_full_export_flag())


class RetentionOffsetTests(unittest.TestCase):
    def test_offset_skips_rows(self):
        db = TursoStore(url="libsql://test", auth_token="t")
        for n in range(5):
            db.upsert_cve({"id": f"CVE-2026-000{n}", "updated_at": "2026-01-01T00:00:00+00:00",
                           "last_alert_state": {"tier": "T2"}})
        ids = [r["id"] for r in db.retention_rows("2026-06-01", 2, offset=3)]
        self.assertEqual(ids, ["CVE-2026-0003", "CVE-2026-0004"])


if __name__ == "__main__":
    unittest.main()
