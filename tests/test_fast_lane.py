"""fast-lane 워터마크 — 실패 · 시간 부족 · 격리 (INVARIANTS §2)"""
import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
for _k in ("SLACK_WEBHOOK_URL", "GEMINI_API_KEY", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"):
    os.environ.setdefault(_k, "test")  # config 가 import 때 확인한다. 테스트는 어디에도 접속하지 않는다

import fast_lane  # noqa: E402
import feed  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
HORIZON = NOW - datetime.timedelta(minutes=1)
T1 = NOW - datetime.timedelta(minutes=30)
T2 = NOW - datetime.timedelta(minutes=20)


def plan(failed=None, deferred=None, done=(), fails=None, quarantined=None):
    return fast_lane.plan_watermark(HORIZON, failed or {}, deferred or {}, done, fails or {},
                                    quarantined or {}, NOW, max_fail=3, retry_h=24)


class PlanWatermarkTests(unittest.TestCase):
    def test_nothing_failed_moves_to_the_horizon(self):
        mark, fails, quarantined, newly = plan()
        self.assertEqual((mark, fails, quarantined, newly), (HORIZON, {}, {}, []))

    def test_failure_holds_the_watermark_and_counts(self):
        mark, fails, quarantined, newly = plan(failed={"CVE-1": T2, "CVE-2": T1})
        self.assertEqual(mark, T1 - datetime.timedelta(seconds=1))
        self.assertEqual(fails, {"CVE-1": 1, "CVE-2": 1})
        self.assertEqual((quarantined, newly), ({}, []))

    def test_third_failure_quarantines_and_releases_the_watermark(self):
        mark, fails, quarantined, newly = plan(failed={"CVE-1": T1}, fails={"CVE-1": 2})
        self.assertEqual(mark, HORIZON)
        self.assertEqual(newly, ["CVE-1"])
        self.assertEqual(quarantined, {"CVE-1": NOW.isoformat()})
        self.assertEqual(fails, {"CVE-1": 3})

    def test_deferred_holds_the_watermark_without_counting(self):
        fails = {}
        for _ in range(5):
            mark, fails, quarantined, newly = plan(deferred={"CVE-1": T1}, fails=fails)
            self.assertEqual(mark, T1 - datetime.timedelta(seconds=1))
            self.assertEqual((fails, quarantined, newly), ({}, {}, []), "시간 부족은 실패가 아니다")

    def test_success_clears_count_and_quarantine(self):
        old = (NOW - datetime.timedelta(hours=30)).isoformat()
        mark, fails, quarantined, _ = plan(done=["CVE-1"], fails={"CVE-1": 3}, quarantined={"CVE-1": old})
        self.assertEqual((mark, fails, quarantined), (HORIZON, {}, {}))

    def test_failed_retry_is_requarantined_then_given_up(self):
        old = (NOW - datetime.timedelta(hours=30)).isoformat()
        mark, fails, quarantined, newly = plan(failed={"CVE-1": T1}, fails={"CVE-1": 3}, quarantined={"CVE-1": old})
        self.assertEqual(mark, HORIZON, "격리된 CVE 는 워터마크를 붙잡지 않는다")
        self.assertEqual(quarantined, {"CVE-1": NOW.isoformat()}, "retry_h 뒤에 다시 본다")
        self.assertEqual((fails, newly), ({"CVE-1": 4}, []))
        mark, fails, quarantined, _ = plan(failed={"CVE-1": T1}, fails={"CVE-1": 9}, quarantined={"CVE-1": old})
        self.assertEqual((mark, fails, quarantined), (HORIZON, {}, {}), "일곱 번 더 실패하면 놓는다")

    def test_deferred_retry_of_a_quarantined_cve_does_not_pull_the_watermark_back(self):
        old = (NOW - datetime.timedelta(hours=30)).isoformat()
        mark, _, quarantined, _ = plan(deferred={"CVE-1": T1}, fails={"CVE-1": 3}, quarantined={"CVE-1": old})
        self.assertEqual(mark, HORIZON)
        self.assertEqual(quarantined, {"CVE-1": old})


class RetryQuarantinedTests(unittest.TestCase):
    def test_expired_quarantine_is_added_once(self):
        now = datetime.datetime.now(UTC)
        state = ({"CVE-1": 3, "CVE-2": 3, "CVE-3": 3},
                 {"CVE-1": (now - datetime.timedelta(hours=30)).isoformat(),   # 기간 끝
                  "CVE-2": (now - datetime.timedelta(hours=2)).isoformat(),    # 격리 중
                  "CVE-3": (now - datetime.timedelta(hours=30)).isoformat()})  # 변경분에 이미 있다
        changes = [feed.Change("CVE-3", T1)]
        with mock.patch.object(fast_lane.pstate, "read_failure_state", return_value=state):
            out = fast_lane._retry_quarantined(changes, T2)
        self.assertEqual([(c.cve_id, c.batch_at) for c in out], [("CVE-3", T1), ("CVE-1", T2)])


class CatchupHorizonTests(unittest.TestCase):
    def test_empty_catchup_window_moves_to_its_end(self):
        now = datetime.datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
        since = now - datetime.timedelta(hours=60)
        batch = {"fetchTime": (since - datetime.timedelta(hours=1)).isoformat(), "new": [], "updated": []}
        with mock.patch.object(feed, "_load_batches", return_value=([batch], True)):
            changes, horizon = feed.changes_since(since, now=now, prefill=False)
        self.assertEqual(changes, [])
        self.assertEqual(horizon, since + datetime.timedelta(hours=feed.CATCHUP_MAX_HOURS))

    def test_uncovered_window_does_not_move(self):
        now = datetime.datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
        since = now - datetime.timedelta(hours=60)
        batch = {"fetchTime": (now + datetime.timedelta(hours=1)).isoformat(), "new": [], "updated": []}
        with mock.patch.object(feed, "_load_batches", return_value=([batch], False)):
            _, horizon = feed.changes_since(since, now=now, prefill=False)
        self.assertEqual(horizon, since)


if __name__ == "__main__":
    unittest.main()
