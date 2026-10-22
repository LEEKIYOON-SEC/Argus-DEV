import json
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
        self.asked = []

    def get_rule_rows(self, ids, days=90):
        if self.fail:
            raise RuntimeError("조회 실패")
        self.asked.append(list(ids))
        return {i: self.rows[i] for i in ids if i in self.rows}

    def get_rule_recheck_candidates(self, limit=10):
        self.limits.append(limit)
        return self.regular[:limit]

    def upsert_cve(self, data):
        self.writes.append(dict(data))


def row(cve, has_rules, checked=None, kev=False, cvss=0.0, epss=0.0):
    return {"id": cve, "has_official_rules": has_rules, "last_rule_check_at": checked,
            "rules_snapshot": None, "is_kev": kev, "cvss_score": cvss, "epss_score": epss}


def lacking(*cves):
    """스냅샷에 지금 색인의 룰이 빠진 CVE (rule_manager.missing 대신)"""
    return lambda cve, _snapshot: cve in cves


def ids(rows):
    return [r["id"] for r in rows]


class DueTests(unittest.TestCase):
    """스냅샷에 지금 색인의 룰이 빠졌고 이 색인으로 아직 다시 보지 않은 CVE 만 — 룰이 없던 것과 있던 것으로 나눈다"""

    def test_only_rows_missing_rules_not_yet_seen_with_this_index(self):
        rows = {"CVE-2026-0001": row("CVE-2026-0001", False),
                "CVE-2026-0002": row("CVE-2026-0002", True, "2026-10-20T10:00:00+09:00"),
                "CVE-2026-0003": row("CVE-2026-0003", True, "2026-10-25T13:40:00+09:00"),
                "CVE-2026-0004": row("CVE-2026-0004", True, "2026-10-25T13:39:59+09:00"),
                "CVE-2026-0005": row("CVE-2026-0005", False)}
        fresh, known = rr.due(rows, BUILT, lacking("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"))
        self.assertEqual(ids(fresh), ["CVE-2026-0001"], "0005 는 스냅샷이 색인과 같다")
        self.assertEqual(ids(known), ["CVE-2026-0002", "CVE-2026-0004"],
                         "색인을 만들고 한 시간 안에 본 것(0004)은 옛 색인으로 봤을 수 있어 한 번 더, 그 뒤에 본 것(0003)은 "
                         "넘어간다 — 시간대가 달라도 시각으로 비교한다(KST 13:40 = UTC 04:40)")

    def test_most_important_first(self):
        rows = {c: row(c, False, kev=k, cvss=s, epss=e) for c, k, s, e in (
            ("CVE-2026-0001", False, 9.8, 0.1), ("CVE-2026-0002", True, 5.0, 0.0),
            ("CVE-2026-0003", False, 9.8, 0.5), ("CVE-2026-0004", True, 9.1, 0.0))}
        fresh, _ = rr.due(rows, BUILT, lambda *_: True)
        self.assertEqual(ids(fresh), ["CVE-2026-0004", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"],
                         "KEV → CVSS → EPSS (기존 재확인과 같은 순서)")

    def test_without_build_time_nothing_is_due(self):
        rows = {"CVE-2026-0001": row("CVE-2026-0001", False)}
        self.assertEqual(rr.due(rows, "", lambda *_: True), ([], []), "옛 색인(generated_at 없음)")
        self.assertEqual(rr.due(rows, "언젠가", lambda *_: True), ([], []))


class PlanTests(unittest.TestCase):
    """알림 예산은 그대로 — 룰이 빠진 CVE 가 먼저, 남는 자리는 기존 재확인 대상"""

    def test_missing_first_then_regular_within_budget(self):
        rows = {f"CVE-2026-000{i}": row(f"CVE-2026-000{i}", i > 3) for i in range(1, 6)}
        db = FakeStore(rows, regular=[row("CVE-2026-0001", False), row("CVE-2025-1111", False),
                                      row("CVE-2025-2222", False)])
        candidates, known = rr.plan(db, sorted(rows) + ["CVE-2026-9999"], BUILT, 5, lambda *_: True)
        self.assertEqual(ids(candidates), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2025-1111"],
                         "기존 대상과 겹치는 CVE 는 한 번만")
        self.assertEqual(db.limits, [2])
        self.assertEqual(ids(known), ["CVE-2026-0004", "CVE-2026-0005"])

    def test_missing_fills_the_budget_and_regular_is_not_queried(self):
        rows = {f"CVE-2026-000{i}": row(f"CVE-2026-000{i}", False) for i in range(1, 5)}
        db = FakeStore(rows, regular=[row("CVE-2025-1111", False)])
        candidates, _ = rr.plan(db, sorted(rows), BUILT, 3, lambda *_: True)
        self.assertEqual(len(candidates), 3)
        self.assertEqual(db.limits, [], "자리가 없으면 기존 대상을 조회하지 않는다")

    def test_lookup_failure_falls_back_to_regular(self):
        db = FakeStore({}, regular=[row("CVE-2025-1111", False)], fail=True)
        candidates, known = rr.plan(db, ["CVE-2026-0001"], BUILT, 10, lambda *_: True)
        self.assertEqual((ids(candidates), known), (["CVE-2025-1111"], []))

    def test_old_index_keeps_previous_behavior(self):
        db = FakeStore({"CVE-2026-0001": row("CVE-2026-0001", False)}, regular=[row("CVE-2025-1111", False)])
        candidates, known = rr.plan(db, ["CVE-2026-0001"], "", 10, lambda *_: True)
        self.assertEqual((ids(candidates), known, db.limits, db.asked), (["CVE-2025-1111"], [], [10], []))


def net(engine, source, sid, rev=1):
    return {"engine": engine, "source": source, "url": "", "path": f"{source}:sid{sid}", "license": "GPLv2",
            "code": f'alert http any any -> any any ( msg:"SERVER-WEBAPP x"; reference:cve,2026-109618; '
                    f'sid:{sid}; rev:{rev}; )'}


NUCLEI = {"engine": "nuclei", "source": "nuclei-templates", "license": "MIT", "link_only": True,
          "path": "http/cves/2026/CVE-2026-109618.yaml",
          "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml"}
YARA_NO_LICENSE = {"engine": "yara", "source": "YARA Forge", "license_url": "N/A",
                   "url": "https://github.com/SIFalcon/Detection/blob/2d7c/a.yar"}
YARA_DRL = {"engine": "yara", "source": "YARA Forge", "author": "F",
            "license_url": "https://github.com/Neo23x0/signature-base/blob/94a1c48d/LICENSE",
            "url": "https://github.com/Neo23x0/signature-base/blob/278165d7/yara/b.yar#L2-L31"}
# 2026-10-22 운영 색인의 CVE-2026-109618 과 같은 꼴(본문만 줄였다) + 라이선스가 다른 YARA 둘
INDEX = {"CVE-2026-109618": [NUCLEI,
                             net("snort2", "Snort 2.9 Community", 67359), net("snort2", "Snort 2.9 Community", 67375),
                             net("snort3", "Snort 3 Community", 67359), net("snort3", "Snort 3 Community", 67375),
                             YARA_NO_LICENSE, YARA_DRL]}


class MissingTests(unittest.TestCase):
    """스냅샷을 지금 색인과 견준다 — search_public_only 가 고를 룰 가운데 스냅샷에 없는 것이 있으면 다시 본다"""

    def setUp(self):
        patches = [mock.patch.object(rm, "_index", return_value=INDEX),
                   mock.patch.object(rm, "_fetch_text", lambda e: e.get("code") or "rule b {}")]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def made_now(self):
        rules, complete = rm.RuleManager().search_public_only("CVE-2026-109618")
        self.assertTrue(complete)
        return json.loads(json.dumps(rules))  # DB 를 거친 꼴

    def test_snapshot_without_the_index_rules_is_missing(self):
        self.assertTrue(rm.missing("CVE-2026-109618", None), "분석 전이라 스냅샷이 없다")
        empty = {"sigma": None, "network": [], "yara": None, "nuclei": None, "splunk": None}
        self.assertTrue(rm.missing("CVE-2026-109618", empty), "운영의 CVE-2026-109618 — 색인에 Snort 룰이 있는데 비어 있다")
        self.assertTrue(rm.missing("CVE-2026-109618", {**empty, "nuclei": rm._pack(NUCLEI)}))
        self.assertFalse(rm.missing("CVE-2026-0000", None), "색인에 없는 CVE")

    def test_snapshot_made_from_this_index_misses_nothing(self):
        snap = self.made_now()
        self.assertEqual([r["engine"] for r in snap["network"]], ["snort2", "snort3", "snort2"])
        self.assertEqual(snap["yara"]["url"], YARA_DRL["url"], "본문을 실을 수 있는 YARA 가 앞선다")
        self.assertFalse(rm.missing("CVE-2026-109618", snap))

    def test_new_revision_of_the_same_rule_is_not_missing(self):
        snap = self.made_now()
        for r in snap["network"]:
            r["code"] = r["code"].replace("rev:1", "rev:2")
        self.assertFalse(rm.missing("CVE-2026-109618", snap), "네트워크 룰은 출처와 SID 로 견준다")

    def test_other_rule_or_moved_link_is_missing(self):
        snap = self.made_now()
        snap["network"][2] = rm._pack(net("suricata5", "Suricata 5 ET Open", 2010902)) | {"code": "sid:2010902;"}
        self.assertTrue(rm.missing("CVE-2026-109618", snap), "고를 룰(snort2 sid 67375)이 빠졌다")
        snap = self.made_now()
        snap["yara"]["url"] = "https://github.com/Neo23x0/signature-base/blob/3ce6640c/yara/b.yar#L2-L31"
        self.assertTrue(rm.missing("CVE-2026-109618", snap), "YARA Forge 가 링크를 새 커밋으로 옮겼다")


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
    """색인을 만든 시각(generated_at)과 색인에 있는 CVE 는 재확인이 읽는다 — 옛 색인에는 만든 시각이 없다"""

    def setUp(self):
        self.saved = (rm._INDEX, rm._INDEX_OK, dict(rm._META))
        rm._INDEX, rm._INDEX_OK = None, False

    def tearDown(self):
        rm._INDEX, rm._INDEX_OK = self.saved[0], self.saved[1]
        rm._META.clear()
        rm._META.update(self.saved[2])

    def test_reads_build_time_and_indexed_ids(self):
        payload = {"generated_at": BUILT, "rules": {"CVE-2026-109618": [], "CVE-2026-0001": []}}
        with mock.patch.object(rm.pages, "fetch_published_json", return_value=payload):
            self.assertEqual((rm.built_at(), sorted(rm.indexed_ids())), (BUILT, ["CVE-2026-0001", "CVE-2026-109618"]))

    def test_old_index_has_no_build_time(self):
        with mock.patch.object(rm.pages, "fetch_published_json", return_value={"rules": {}}):
            self.assertEqual(rm.built_at(), "")


if __name__ == "__main__":
    unittest.main()
