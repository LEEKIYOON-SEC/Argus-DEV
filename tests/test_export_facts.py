import datetime as dt
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import export_dashboard_data as ex  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def state(**over):
    base = {
        "title": "Acme Widget RCE", "title_ko": "Acme Widget 원격 코드 실행",
        "description": "A remote code execution vulnerability in Acme Widget before 2.1.",
        "desc_ko": "Acme Widget 2.1 이전에 원격 코드 실행 취약점이 있습니다.",
        "assigner": "acme", "cwe": ["CWE-94"], "published": "2026-09-01",
        "affected": [{"vendor": "Acme", "product": "Widget", "versions": "2.1 이전", "patch_version": "2.1"}],
        "references": ["https://acme.example/advisory"], "cvss_vector": "CVSS:3.1/AV:N",
        "cvss_version": "3.1", "tier": "T2",
    }
    base.update(over)
    return base


def row(cid, st, updated=None):
    return {"id": cid, "cvss_score": 9.8, "epss_score": 0.2, "is_kev": False,
            "last_alert_state": st, "last_alert_at": None,
            "updated_at": updated or NOW.isoformat(), "rules_snapshot": {}, "has_official_rules": False}


class FakeDB:
    def __init__(self, rows):
        self.rows = rows

    def export_rows(self, since, days=90):
        return [r for r in self.rows if since is None or r["updated_at"] >= since]

    def live_ids(self, days=90):
        return {r["id"] for r in self.rows}

    full_flag = False
    cleared = 0

    def has_full_export_flag(self):
        return self.full_flag

    def clear_full_export_flag(self):
        self.full_flag = False
        self.cleared += 1


class FactsOfTests(unittest.TestCase):
    """화면에 나간 제목·설명이 어디서 왔는지와 원문을 남긴다"""

    def test_ai_translation_and_summary(self):
        facts = {}
        ex.export_cves(FakeDB([row("CVE-2026-0001", state())]), facts=facts)
        f = facts["CVE-2026-0001"]
        self.assertEqual(f["o"], ["ai", "ai"])
        self.assertEqual(f["t"], "Acme Widget RCE")
        self.assertTrue(f["d"].startswith("A remote code execution"))
        self.assertEqual(f["a"], "acme")

    def test_untranslated_text_is_source(self):
        facts = {}
        # 번역 실패 시 main.py 는 원문 앞부분(200자)을 desc_ko 로 둔다
        st = state(title_ko="Acme Widget RCE", desc_ko="A remote code execution vulnerability")
        ex.export_cves(FakeDB([row("CVE-2026-0002", st)]), facts=facts)
        self.assertEqual(facts["CVE-2026-0002"]["o"], ["source", "source"],
                         "번역에 실패해 원문을 그대로 둔 값은 AI 생성이 아니다")

    def test_placeholder_title_is_argus_generated(self):
        facts = {}
        cves = ex.export_cves(FakeDB([row("CVE-2026-0003", state(title="N/A", title_ko=""))]), facts=facts)
        self.assertEqual(cves[0]["title"], "Widget 취약점")
        self.assertEqual(facts["CVE-2026-0003"]["o"][0], "argus")
        self.assertNotIn("t", facts["CVE-2026-0003"], "없는 원 제목을 만들지 않는다")

    def test_long_description_is_capped(self):
        facts = {}
        ex.export_cves(FakeDB([row("CVE-2026-0004", state(description="x " * 3000))]), facts=facts)
        d = facts["CVE-2026-0004"]["d"]
        self.assertLessEqual(len(d), ex._FACT_DESC_MAX + 1)
        self.assertTrue(d.endswith("…"))

    def test_product_source_only_when_recorded(self):
        facts = {}
        st = state(affected=[{"vendor": "Acme", "product": "Widget", "versions": "정보 없음", "source": "CISA KEV"},
                             {"vendor": "Acme", "product": "Widget", "versions": "1.0", "source": "CISA KEV"},
                             {"vendor": "Acme", "product": "Tool", "versions": "1.0"}])
        ex.export_cves(FakeDB([row("CVE-2026-0005", st)]), facts=facts)
        self.assertEqual(facts["CVE-2026-0005"]["p"], [["Acme", "Widget", "CISA KEV"]])

    def test_cve_rows_keep_their_schema(self):
        plain = ex.export_cves(FakeDB([row("CVE-2026-0006", state())]))
        with_facts = ex.export_cves(FakeDB([row("CVE-2026-0006", state())]), facts={})
        self.assertEqual(plain, with_facts, "원문 사실은 cves.json 행에 섞지 않는다")
        self.assertNotIn("o", plain[0])


class MergeTests(unittest.TestCase):
    def test_fresh_wins_carried_fills_and_dropped_rows_leave(self):
        cve_data = [{"id": "CVE-A"}, {"id": "CVE-B"}]
        fresh = {"CVE-A": {"o": ["ai", "ai"], "t": "new"}}
        carried = {"CVE-A": {"t": "old"}, "CVE-B": {"t": "kept"}, "CVE-GONE": {"t": "x"}}
        out = ex.merge_facts(cve_data, fresh, carried, {"CVE-A"})
        self.assertEqual(out, {"CVE-A": fresh["CVE-A"], "CVE-B": {"t": "kept"}})


class FetchLiveTests(unittest.TestCase):
    def _run(self, effect=None, value=None):
        with mock.patch.object(ex.pages, "fetch_published_json", side_effect=effect, return_value=value):
            return ex.fetch_live_facts()

    def test_missing_file(self):
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        self.assertEqual(self._run(effect=err), (None, "missing"))

    def test_transient_error(self):
        self.assertEqual(self._run(effect=urllib.error.URLError("reset")), (None, "error"))
        self.assertEqual(self._run(effect=urllib.error.HTTPError("u", 503, "x", {}, None)), (None, "error"))

    def test_schema_mismatch_is_missing(self):
        self.assertEqual(self._run(value={"schema": 99, "facts": {}}), (None, "missing"))

    def test_ok(self):
        self.assertEqual(self._run(value={"schema": 1, "facts": {"CVE-A": {"t": "x"}}}), ({"CVE-A": {"t": "x"}}, "ok"))


class MainTests(unittest.TestCase):
    """증분 export 와 같은 규칙으로 원문 사실 파일을 유지한다"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        old = (NOW - dt.timedelta(hours=3)).isoformat()
        self.db = FakeDB([row("CVE-2026-0101", state(), updated=NOW.isoformat()),
                          row("CVE-2026-0102", state(title="Old one", title_ko="예전 것"), updated=old)])
        self.previous = [ex.export_cves(self.db)[1]]

    def _main(self, facts_result, previous=True, epss=None, crash=None):
        prev = (self.previous, (NOW - dt.timedelta(hours=1)).isoformat()) if previous else (None, None)
        patches = [
            mock.patch.object(ex.enrichment_sources, "load_epss_full", return_value=epss),
            mock.patch.object(ex, "_get_db", return_value=self.db),
            mock.patch.object(ex, "load_previous_export", return_value=prev),
            mock.patch.object(ex, "fetch_live_facts", return_value=facts_result),
            mock.patch.object(ex, "fetch_live_products", return_value=getattr(self, "live_products", {})),
            mock.patch.object(ex, "publish_weekly_report"),
            mock.patch.object(ex, "apply_retention_policy", return_value=0),
        ]
        if crash:
            patches.append(mock.patch.object(ex, crash, side_effect=RuntimeError("도중 실패")))
        for p in patches:
            p.start()
        try:
            ex.main(self.tmp)
        finally:
            for p in reversed(patches):
                p.stop()
        path = os.path.join(self.tmp, ex.FACTS_FILE)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_incremental_merges_carried(self):
        out = self._main(({"CVE-2026-0102": {"o": ["ai", "ai"], "t": "Old one (carried)"}}, "ok"))
        self.assertEqual(out["schema"], 1)
        self.assertEqual(set(out["facts"]), {"CVE-2026-0101", "CVE-2026-0102"})
        self.assertEqual(out["facts"]["CVE-2026-0102"]["t"], "Old one (carried)", "갱신 안 된 행은 배포본 값을 잇는다")
        self.assertEqual(out["facts"]["CVE-2026-0101"]["t"], "Acme Widget RCE")

    def test_missing_live_file_bootstraps_full_export(self):
        out = self._main((None, "missing"))
        self.assertEqual(out["facts"]["CVE-2026-0102"]["t"], "Old one", "전량 export 로 모든 행을 채운다")

    def test_transient_error_leaves_file_for_carry_forward(self):
        self.assertIsNone(self._main((None, "error")),
                          "일부 행만 담긴 파일로 덮어쓰지 않는다 — 배포 단계가 배포본을 이월한다")

    def test_unreadable_product_index_falls_back_to_full_export(self):
        self.live_products = None
        out = self._main(({"CVE-2026-0102": {"o": ["ai", "ai"], "t": "Old one (carried)"}}, "ok"))
        self.assertEqual(out["facts"]["CVE-2026-0102"]["t"], "Old one",
                         "직전 제품 인덱스 없이 병합하지 않는다 — 전량 export 로 다시 만든다")

    def test_full_export_request_is_cleared_only_after_the_files_are_written(self):
        self.db.full_flag = True
        with self.assertRaises(RuntimeError):
            self._main(({}, "ok"), crash="export_stats")
        self.assertTrue(self.db.full_flag, "도중에 죽으면 요청이 남아 다음 회차가 전량 export 한다")
        self._main(({}, "ok"))
        self.assertFalse(self.db.full_flag)
        self.assertEqual(self.db.cleared, 1)

    def test_no_store_writes_nothing_and_fails(self):
        with mock.patch.object(ex, "_get_db", return_value=None):
            with self.assertRaises(SystemExit) as stop:
                ex.main(self.tmp)
        self.assertEqual(stop.exception.code, 1)
        self.assertEqual(os.listdir(self.tmp), [], "빈 cves.json 을 쓰면 배포 단계가 대시보드를 비운다")

    def test_full_export_writes_all(self):
        out = self._main(({}, "ok"), previous=False)
        self.assertEqual(set(out["facts"]), {"CVE-2026-0101", "CVE-2026-0102"})

    def _cves(self):
        with open(os.path.join(self.tmp, "cves.json"), encoding="utf-8") as f:
            return {r["id"]: r for r in json.load(f)}

    def test_epss_is_refreshed_for_every_row_on_export(self):
        epss = {"CVE-2026-0101": (0.51234, 0.97), "CVE-2026-0102": (0.00123, 0.31)}
        with mock.patch.object(ex, "_EPSS_MIN_ROWS", 1):
            self._main(({}, "ok"), epss=epss)
        rows = self._cves()
        self.assertEqual((rows["CVE-2026-0101"]["epss"], rows["CVE-2026-0101"]["epss_percentile"]), (0.51234, 0.97))
        self.assertEqual((rows["CVE-2026-0102"]["epss"], rows["CVE-2026-0102"]["epss_percentile"]), (0.00123, 0.31),
                         "이월된 행도 전량 파일 값으로 맞춘다")

    def test_epss_keeps_db_values_without_the_file(self):
        self._main(({}, "ok"), epss=None)
        self.assertEqual({r["epss"] for r in self._cves().values()}, {0.2}, "파일을 못 받으면 DB 값 그대로")


class RetentionPagingTests(unittest.TestCase):
    """남기는 행(악용 중)이 첫 쪽을 채워도 그 뒤의 행까지 본다"""

    class DB:
        def __init__(self, rows):
            self.rows = rows
            self.calls = []

        def retention_rows(self, before, limit, offset=0, **filters):
            self.calls.append(offset)
            return self.rows[offset:offset + limit]

        def delete_rows(self, ids):
            gone = set(ids)
            self.rows = [r for r in self.rows if r["id"] not in gone]
            return len(gone)

    def test_kept_rows_are_skipped_on_the_next_page(self):
        keep = [{"id": f"CVE-2020-{n:05d}", "is_kev": True, "last_alert_state": {"tier": "T0", "is_kev": True}}
                for n in range(5)]
        drop = [{"id": f"CVE-2021-{n:05d}", "is_kev": False, "cvss_score": 5.0,
                 "last_alert_state": {"tier": "T2"}} for n in range(4)]
        db = self.DB(keep + drop)
        with mock.patch.object(ex, "RETENTION_BATCH", 3):
            done, kept = ex._retire(db, "2026-01-01", db.delete_rows)
        self.assertEqual((done, kept), (4, 5))
        self.assertEqual([r["id"] for r in db.rows], [r["id"] for r in keep])
        self.assertEqual(db.calls[:3], [0, 3, 5])

    def test_stops_after_the_page_limit(self):
        keep = [{"id": f"CVE-2020-{n:05d}", "is_kev": True, "last_alert_state": {"tier": "T0", "is_kev": True}}
                for n in range(50)]
        db = self.DB(keep)
        with mock.patch.object(ex, "RETENTION_BATCH", 2), mock.patch.object(ex, "RETENTION_PAGES", 4):
            self.assertEqual(ex._retire(db, "2026-01-01", db.delete_rows), (0, 8))
        self.assertEqual(len(db.calls), 4)


class EpssRefreshTests(unittest.TestCase):
    """내보낼 때 전량 EPSS 로 점수를 다시 채운다 — DB 의 점수는 다시 처리할 때만 바뀌어 낡는다"""

    def test_overwrites_present_and_keeps_absent(self):
        rows = [{"id": "CVE-A", "epss": 0.1, "epss_percentile": 0.5},
                {"id": "CVE-B", "epss": 0, "epss_percentile": 0},
                {"id": "CVE-C", "epss": 0.3, "epss_percentile": 0.9}]
        epss = {"CVE-A": (0.2, 0.6), "CVE-B": (0.00042, 0.12)}
        with mock.patch.object(ex, "_EPSS_MIN_ROWS", 1):
            self.assertEqual(ex.refresh_epss(rows, epss), 2)
            self.assertEqual(ex.refresh_epss(rows, epss), 0, "두 번째 적용은 바꾸는 것이 없다")
        self.assertEqual([(r["epss"], r["epss_percentile"]) for r in rows], [(0.2, 0.6), (0.00042, 0.12), (0.3, 0.9)],
                         "파일에 없는 CVE 는 0 으로 만들지 않는다")

    def test_small_or_missing_file_changes_nothing(self):
        rows = [{"id": "CVE-A", "epss": 0.1, "epss_percentile": 0.5}]
        self.assertEqual(ex.refresh_epss(rows, None), 0)
        self.assertEqual(ex.refresh_epss(rows, {"CVE-A": (0.9, 0.99)}), 0, "잘린 파일로 보고 쓰지 않는다")
        self.assertEqual(rows[0]["epss"], 0.1)


if __name__ == "__main__":
    unittest.main()
