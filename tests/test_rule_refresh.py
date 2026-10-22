import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import rule_manager as rm  # noqa: E402
import rule_refresh as rr  # noqa: E402

BUILT = "2026-10-25T03:40:00+00:00"


class FakeStore:
    def __init__(self, rows, regular=(), fail=False):
        self.rows = rows
        self.regular = list(regular)
        self.fail = fail
        self.writes = []
        self.limits = []

    def get_cves(self, ids):
        if self.fail:
            raise RuntimeError("조회 실패")
        return {i: self.rows[i] for i in ids if i in self.rows}, set(ids)

    def get_rule_recheck_candidates(self, limit=10):
        self.limits.append(limit)
        return self.regular[:limit]

    def upsert_cve(self, data):
        self.writes.append(dict(data))


def row(cve, has_rules, checked=None):
    return {"id": cve, "has_official_rules": has_rules, "last_rule_check_at": checked}


class DueTests(unittest.TestCase):
    """색인을 만든 뒤로 다시 보지 않은, 추적 중인 CVE 만 — 룰이 없던 것과 있던 것으로 나눈다"""

    def test_splits_by_existing_rules_and_skips_checked_after_build(self):
        rows = {"CVE-2026-0001": row("CVE-2026-0001", False),
                "CVE-2026-0002": row("CVE-2026-0002", True, "2026-10-20T10:00:00+09:00"),
                "CVE-2026-0003": row("CVE-2026-0003", True, "2026-10-25T13:00:00+09:00"),
                "CVE-2026-0005": row("CVE-2026-0005", True, "2026-10-25T12:39:59+09:00")}
        grown = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"]
        fresh, known = rr.due(rows, grown, BUILT)
        self.assertEqual([r["id"] for r in fresh], ["CVE-2026-0001"])
        self.assertEqual([r["id"] for r in known], ["CVE-2026-0002", "CVE-2026-0005"],
                         "시간대가 달라도 시각으로 비교한다(KST 12:39:59 = UTC 03:39:59, 색인보다 먼저)")

    def test_without_build_time_nothing_is_due(self):
        rows = {"CVE-2026-0001": row("CVE-2026-0001", False)}
        self.assertEqual(rr.due(rows, ["CVE-2026-0001"], ""), ([], []), "옛 색인(generated_at 없음)")
        self.assertEqual(rr.due(rows, ["CVE-2026-0001"], "언젠가"), ([], []))


class PlanTests(unittest.TestCase):
    """알림 예산은 그대로 — 룰이 늘어난 CVE 가 먼저, 남는 자리는 기존 재확인 대상"""

    def test_grown_first_then_regular_within_budget(self):
        rows = {f"CVE-2026-000{i}": row(f"CVE-2026-000{i}", i > 3) for i in range(1, 6)}
        db = FakeStore(rows, regular=[row("CVE-2026-0001", False), row("CVE-2025-1111", False),
                                      row("CVE-2025-2222", False)])
        candidates, known = rr.plan(db, sorted(rows), BUILT, max_recheck=5)
        self.assertEqual([r["id"] for r in candidates],
                         ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2025-1111"],
                         "기존 대상과 겹치는 CVE 는 한 번만")
        self.assertEqual(db.limits, [2])
        self.assertEqual([r["id"] for r in known], ["CVE-2026-0004", "CVE-2026-0005"])

    def test_grown_fills_the_budget_and_regular_is_not_queried(self):
        rows = {f"CVE-2026-000{i}": row(f"CVE-2026-000{i}", False) for i in range(1, 5)}
        db = FakeStore(rows, regular=[row("CVE-2025-1111", False)])
        candidates, _ = rr.plan(db, sorted(rows), BUILT, max_recheck=3)
        self.assertEqual(len(candidates), 3)
        self.assertEqual(db.limits, [], "자리가 없으면 기존 대상을 조회하지 않는다")

    def test_lookup_failure_falls_back_to_regular(self):
        db = FakeStore({}, regular=[row("CVE-2025-1111", False)], fail=True)
        candidates, known = rr.plan(db, ["CVE-2026-0001"], BUILT, max_recheck=10)
        self.assertEqual(([r["id"] for r in candidates], known), (["CVE-2025-1111"], []))

    def test_old_index_keeps_previous_behavior(self):
        db = FakeStore({}, regular=[row("CVE-2025-1111", False)])
        candidates, known = rr.plan(db, [], "", max_recheck=10)
        self.assertEqual(([r["id"] for r in candidates], known, db.limits), (["CVE-2025-1111"], [], [10]))


class RefreshKnownTests(unittest.TestCase):
    """이미 룰이 있던 CVE — 알림 없이 스냅샷만, 못 찾은 것으로 지우지 않는다"""

    def run_refresh(self, results, rows=None, **kw):
        db = FakeStore({})
        calls = []

        def search(cve_id):
            calls.append(cve_id)
            return results[cve_id]

        rows = rows or [row(c, True) for c in results]
        done = rr.refresh_known(db, search, rows, now=lambda: "NOW", soon=lambda: "SOON", **kw)
        return done, db.writes, calls

    def test_writes_new_snapshot_when_rules_found(self):
        snort = {"network": [{"engine": "snort3", "code": "alert http (...)"}], "nuclei": {"engine": "nuclei"}}
        done, writes, _ = self.run_refresh({"CVE-2026-0001": (snort, True)})
        self.assertEqual(done, 1)
        self.assertEqual(writes, [{"id": "CVE-2026-0001", "has_official_rules": True, "rules_snapshot": snort,
                                   "last_rule_check_at": "NOW", "updated_at": "NOW"}])

    def test_keeps_old_snapshot_when_nothing_found_or_incomplete(self):
        empty = {"sigma": None, "network": [], "yara": None, "nuclei": None, "splunk": None}
        done, writes, _ = self.run_refresh({"CVE-2026-0001": (empty, True), "CVE-2026-0002": (empty, False)})
        self.assertEqual(done, 0)
        self.assertEqual(writes, [{"id": "CVE-2026-0001", "last_rule_check_at": "NOW", "updated_at": "NOW"},
                                  {"id": "CVE-2026-0002", "last_rule_check_at": "SOON", "updated_at": "NOW"}],
                         "rules_snapshot · has_official_rules 는 건드리지 않는다")

    def test_stops_at_deadline(self):
        results = {"CVE-2026-0001": ({"nuclei": {"engine": "nuclei"}}, True),
                   "CVE-2026-0002": ({"nuclei": {"engine": "nuclei"}}, True)}
        ticks = iter([0, 100])
        done, writes, calls = self.run_refresh(results, deadline_ts=50, clock=lambda: next(ticks))
        self.assertEqual((done, calls), (1, ["CVE-2026-0001"]))


class IndexMetaTests(unittest.TestCase):
    """색인의 generated_at · grown 은 재확인이 읽는다 — 옛 색인에는 없다"""

    def setUp(self):
        self.saved = (rm._INDEX, rm._INDEX_OK, dict(rm._META))
        rm._INDEX, rm._INDEX_OK = None, False

    def tearDown(self):
        rm._INDEX, rm._INDEX_OK = self.saved[0], self.saved[1]
        rm._META.clear()
        rm._META.update(self.saved[2])

    def test_reads_grown_and_build_time(self):
        payload = {"generated_at": BUILT, "grown": ["cve-2026-109618"], "rules": {"CVE-2026-109618": []}}
        with mock.patch.object(rm.pages, "fetch_published_json", return_value=payload):
            self.assertEqual(rm.grown(), (["CVE-2026-109618"], BUILT))

    def test_old_index_has_nothing_grown(self):
        with mock.patch.object(rm.pages, "fetch_published_json", return_value={"rules": {}}):
            self.assertEqual(rm.grown(), ([], ""))


if __name__ == "__main__":
    unittest.main()
