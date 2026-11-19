"""소스측 대조 — PoC-in-GitHub 소스(최초 기록 예외 · 최신순) · PoC 색인 날짜 · 이번 시(時) 캐시 · CWE-288 (INVARIANTS §2 · §3)"""
import datetime
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
for _k in ("SLACK_WEBHOOK_URL", "GEMINI_API_KEY", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"):
    os.environ.setdefault(_k, "test")  # config 가 import 때 확인한다. 테스트는 어디에도 접속하지 않는다

import enrichment_sources as es  # noqa: E402
import risk  # noqa: E402
import signal_snapshot as ss  # noqa: E402

# PoC-in-GitHub README 의 실제 꼴을 줄인 것 — 날짜 없는 제목(공개 직후 · 공개 전), 링크 없는 제목,
# 번호가 틀린 제목(실제 README 에 16개), 연도 제목
README = """# PoC in GitHub

## 2026
### CVE-2026-114938
- [a/CVE-2026-114938](https://github.com/a/CVE-2026-114938)
- [b/BigFix-Java4Shell-CVE-2026-114938-Scanner](https://github.com/b/BigFix-Java4Shell-CVE-2026-114938-Scanner)

### CVE-2026-100001 (2026-11-01)

<code>Some description.
</code>

- [c/x](https://github.com/c/x)

### CVE-2026-0002 (2026-01-05)
- [d/z](https://github.com/d/z)

### CVE-2026-0003 (2026-01-06)
링크가 없는 항목

### CVE-2026-30
- [f/CVE-2026-30](https://github.com/f/CVE-2026-30)

## 2025
### CVE-2025-1234 (2025-03-01)
- [e/w](https://github.com/e/w)
"""


def reset_poc():
    es._poc_index.clear()
    es._poc_dates.clear()
    es._poc_counts.clear()
    es._poc_nicks.clear()
    es._nick_spell.clear()
    es._poc_loaded = False
    es._poc_ok = False


# 별칭 — 서로 다른 주인 3명이 같은 이름(표기는 제각각), 한 주인이 두 번 쓴 이름, 페이로드 이름, 대문자로 이어 붙인 이름
NAMED = """# PoC in GitHub

## 2026
### CVE-2026-109618 (2026-10-21)
- [a/PHP2Shell](https://github.com/a/PHP2Shell)
- [b/php2shell-detect](https://github.com/b/php2shell-detect)
- [c/CVE-2026-109618-PHP2Shell-Scanner](https://github.com/c/CVE-2026-109618-PHP2Shell-Scanner)
- [d/aarch64shell-payload](https://github.com/d/aarch64shell-payload)
- [e/Foo2Shell](https://github.com/e/Foo2Shell)
- [e/foo2shell-v2](https://github.com/e/foo2shell-v2)
- [B/PHP2Shell-copy](https://github.com/B/PHP2Shell-copy)

### CVE-2026-109619 (2026-10-21)
- [x/php2shell](https://github.com/x/php2shell)
- [y/php2shell-2](https://github.com/y/php2shell-2)
- [z/php-2-shell](https://github.com/z/php-2-shell)

### CVE-2021-44228 (2021-12-10)
- [p/Log4ShellScanner](https://github.com/p/Log4ShellScanner)
- [q/log4shell](https://github.com/q/log4shell)
- [r/Log4Shell-poc](https://github.com/r/Log4Shell-poc)
- [s/log4shells-notes](https://github.com/s/log4shells-notes)
"""


class PocIndexTests(unittest.TestCase):
    def setUp(self):
        reset_poc()
        self.addCleanup(reset_poc)

    def load(self):
        with mock.patch.object(es, "cache_get", return_value=README.encode()) as get, \
                mock.patch.object(es.requests, "get", side_effect=AssertionError("캐시가 있으면 받지 않는다")):
            idx = es.load_poc_index()
        return idx, get

    def test_index_links_and_dates(self):
        idx, _ = self.load()
        self.assertEqual(set(idx), {"CVE-2026-114938", "CVE-2026-100001", "CVE-2026-0002", "CVE-2025-1234"},
                         "링크가 없는 제목 · 번호가 틀린 제목은 넣지 않는다")
        self.assertNotIn("CVE-2026-0003", idx, "번호가 틀린 제목 아래 링크를 바로 앞 CVE 에 붙이지 않는다")
        self.assertEqual(idx["CVE-2026-114938"][1],
                         "https://github.com/b/BigFix-Java4Shell-CVE-2026-114938-Scanner")
        self.assertEqual(idx["CVE-2026-100001"], ["https://github.com/c/x"], "다음 제목 앞까지만 본다")
        self.assertEqual(es.poc_dates(), {"CVE-2026-100001": "2026-11-01", "CVE-2026-0002": "2026-01-05",
                                          "CVE-2025-1234": "2025-03-01"}, "날짜 없는 제목은 날짜를 만들지 않는다")

    def test_index_is_only_reused_within_this_hour(self):
        _, get = self.load()
        self.assertEqual(get.call_args.args[0], "poc-in-github.md")
        self.assertEqual(get.call_args.kwargs.get("since"), es.this_hour_start(),
                         "24시간 수명이 아니라 이번 시(時)에 받은 것만 쓴다")


class NicknameTests(unittest.TestCase):
    """별칭 — 서로 다른 저장소 주인 3명 이상이 쓴 이름, 표기는 색인 전체에서 가장 많이 쓴 것"""

    def setUp(self):
        reset_poc()
        self.addCleanup(reset_poc)
        with mock.patch.object(es, "cache_get", return_value=NAMED.encode()):
            es.load_poc_index()

    def test_three_distinct_owners_make_a_nickname(self):
        self.assertEqual(es.poc_nicknames("CVE-2026-109618"), [("PHP2Shell", 3)],
                         "주인 a · b · c 세 명(대소문자만 다른 B 는 b 와 같은 주인) — Foo2Shell 은 한 주인이라 빠진다")
        self.assertEqual(es.poc_count("CVE-2026-109618"), 7, "저장소는 이름과 상관없이 다 센다")

    def test_spelling_is_shared_across_cves(self):
        self.assertEqual(es.poc_nicknames("CVE-2026-109619"), [("PHP2Shell", 3)],
                         "이 CVE 의 저장소는 모두 소문자지만 표기는 색인 전체에서 대문자가 섞인 'PHP2' 를 쓴다")
        self.assertEqual(es.nickname_display("php2shell"), "PHP2Shell")
        self.assertEqual(es.nickname_display("없는이름"), "")

    def test_camel_case_joined_names_count_but_longer_words_do_not(self):
        self.assertEqual(es.poc_nicknames("CVE-2021-44228"), [("Log4Shell", 3)],
                         "Log4ShellScanner 는 잡고 log4shells-notes 는 다른 낱말로 본다")

    def test_nickname_parts(self):
        self.assertEqual(es.nickname_parts("BigFix-Java4Shell-CVE-2026-114938-Scanner"), [("java4shell", "Java4")])
        self.assertEqual(es.nickname_parts("aarch64shell x64shell"), [], "페이로드 이름은 별칭이 아니다")
        self.assertEqual(es.nickname_parts("WordPress Core - Preauth Reflected XSS (XSS2Shell)"), [("xss2shell", "XSS2")])
        self.assertEqual(es.nickname_parts("log4shells"), [])

    def test_tool_names(self):
        with mock.patch.object(es, "nuclei_template", return_value={"name": "WordPress Core < 7.1.1 - Stored XSS (Comment2Shell)"}), \
                mock.patch.object(es, "metasploit_modules", return_value=[{"fullname": "exploit/multi/http/react2shell_rce"}]):
            self.assertEqual(es.tool_nicknames("CVE-2026-93485"),
                             [("Comment2Shell", "nuclei"), ("React2Shell", "metasploit")])
            self.assertEqual(es.tool_nicknames("CVE-2026-93485", nuclei=False, msf=False), [])


class CacheSinceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = mock.patch.object(es, "_CACHE_DIR", self.dir)
        p.start()
        self.addCleanup(p.stop)
        es.cache_put("f.bin", b"data")
        self.path = os.path.join(self.dir, "f.bin")

    def touch(self, when):
        os.utime(self.path, (when, when))

    def test_since_keeps_only_files_from_this_hour(self):
        start = es.this_hour_start()
        self.touch(start - 1)
        self.assertIsNone(es.cache_get("f.bin", since=start), "지난 시(時)에 받은 파일은 다시 받는다")
        self.touch(start + 1)
        self.assertEqual(es.cache_get("f.bin", since=start), b"data")

    def test_ttl_unchanged_without_since(self):
        self.touch(time.time() - 1800)
        self.assertEqual(es.cache_get("f.bin", ttl_hours=1), b"data")
        self.touch(time.time() - 7200)
        self.assertIsNone(es.cache_get("f.bin", ttl_hours=1))

    def test_hour_start(self):
        self.assertEqual(es.this_hour_start(7200 + 59 * 60 + 59), 7200)
        self.assertEqual(es.this_hour_start(7200), 7200)


class FakeStore:
    def __init__(self, rows=None):
        self.rows = rows or {}
        self.snapshots = {}
        self.asked = []

    def get_snapshot_digest(self, key):
        return self.snapshots.get(key, (None, None))[0]

    def get_snapshot_ids(self, key):
        return set(self.snapshots.get(key, (None, set()))[1])

    def save_snapshot(self, key, digest, ids):
        self.snapshots[key] = (digest, set(ids))
        return True

    def get_cves(self, ids):
        ids = list(ids)
        self.asked.append(ids)
        return {i: self.rows[i] for i in ids if i in self.rows}, set(ids)


def days_ago(n):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=n)).date().isoformat()


class PocCatchUpTests(unittest.TestCase):
    """처음 기록할 때 바로 판정할 것 — 공개 90일 이내이거나 날짜가 없고, 아직 추적하지 않는 것"""

    def test_recent_or_undated_and_untracked(self):
        ids = {"CVE-2026-114938", "CVE-2026-100001", "CVE-2026-100002", "CVE-2026-100003", "CVE-2026-0002"}
        dates = {"CVE-2026-100001": days_ago(10), "CVE-2026-100002": days_ago(10),
                 "CVE-2026-100003": days_ago(89), "CVE-2026-0002": days_ago(200)}
        store = FakeStore({"CVE-2026-100002": {"last_alert_state": {"tier": "T2"}},   # 추적 중
                           "CVE-2026-100003": {"last_alert_state": None}})            # 상태 없는 표식 행
        with mock.patch.object(es, "poc_dates", return_value=dates):
            got = ss._poc_catch_up(ids, store)
        self.assertEqual(got, {"CVE-2026-114938", "CVE-2026-100001", "CVE-2026-100003"})
        self.assertNotIn("CVE-2026-0002", store.asked[0], "90일보다 오래된 것은 DB 에 묻지도 않는다")

    def test_nothing_recent_asks_nothing(self):
        store = FakeStore()
        with mock.patch.object(es, "poc_dates", return_value={"CVE-2020-1": days_ago(900)}):
            self.assertEqual(ss._poc_catch_up({"CVE-2020-1"}, store), set())
        self.assertEqual(store.asked, [])


class SweepTests(unittest.TestCase):
    def source(self, ids, catch_up=None, newest_first=False):
        return ss.Source("t", "테스트", False, lambda: set(ids), catch_up=catch_up, newest_first=newest_first)

    def test_default_first_sweep_marks_everything_seen(self):
        store = FakeStore()
        diff = ss._sweep_one(store, self.source({"CVE-2026-1000", "CVE-2026-1001"}), cap=10)
        self.assertEqual(diff.added, [])
        self.assertEqual(store.get_snapshot_ids("t"), {"CVE-2026-1000", "CVE-2026-1001"})

    def test_catch_up_is_judged_newest_first_across_runs(self):
        ids = {"CVE-2026-0002", "CVE-2026-114938", "CVE-2025-99999", "CVE-2026-100001", "CVE-2024-1"}
        pending = {"CVE-2026-0002", "CVE-2026-114938", "CVE-2025-99999", "CVE-2026-100001"}
        src = self.source(ids, catch_up=lambda up, st: pending, newest_first=True)
        store = FakeStore()
        diff = ss._sweep_one(store, src, cap=2)
        self.assertEqual(diff.added, ["CVE-2026-114938", "CVE-2026-100001"], "연도 · 번호가 큰 것부터")
        self.assertEqual(store.get_snapshot_ids("t"), {"CVE-2024-1"}, "바로 판정할 것은 '본 것'에 넣지 않는다")
        ss.commit(store, diff, diff.added)
        diff = ss._sweep_one(store, src, cap=2)
        self.assertEqual(diff.added, ["CVE-2026-0002", "CVE-2025-99999"], "나머지는 다음 실행이 이어받는다")
        ss.commit(store, diff, diff.added)
        self.assertIsNone(ss._sweep_one(store, src, cap=2), "다 처리하면 변화 없음")

    def test_catch_up_of_everything_only_records(self):
        ids = {"CVE-2026-1000", "CVE-2026-1001"}
        store = FakeStore()
        diff = ss._sweep_one(store, self.source(ids, catch_up=lambda up, st: set(up)), cap=10)
        self.assertEqual(diff.added, [], "'본 것'이 비면 다음 회차가 집합을 읽지 못한다 — 이번은 기록만")
        self.assertEqual(store.get_snapshot_ids("t"), ids)

    def test_order_for_other_sources_is_unchanged(self):
        store = FakeStore()
        store.save_snapshot("t", "old", {"CVE-2020-1"})
        diff = ss._sweep_one(store, self.source({"CVE-2020-1", "CVE-2026-0002", "CVE-2026-114938"}), cap=10)
        self.assertEqual(diff.added, ["CVE-2026-0002", "CVE-2026-114938"], "기본은 ID 오름차순")

    def test_poc_source_is_registered_for_the_bulk_lane(self):
        src = ss.SOURCES["poc_in_github"]
        self.assertFalse(src.fast, "T2 근거라 매시 bulk-lane 에서 대조한다")
        self.assertIs(src.catch_up, ss._poc_catch_up)
        self.assertTrue(src.newest_first)
        with mock.patch.object(es, "load_poc_index", return_value={"CVE-2026-114938": ["u"]}):
            self.assertEqual(src.load(), {"CVE-2026-114938"})
        with mock.patch.object(es, "load_poc_index", return_value={}):
            self.assertIsNone(src.load(), "받지 못한 색인을 빈 집합으로 저장하지 않는다")


class SeedSnapshotTests(unittest.TestCase):
    """재시드는 catch_up 이 있는 소스의 스냅샷을 남겨 둔다 — bulk-lane 첫 회차가 최근 것을 판정하며 기록한다"""

    def test_reseed_leaves_poc_to_the_bulk_lane(self):
        import seed_turso
        store = FakeStore()
        store.save_snapshot("cisa_kev_v2", "d", {"CVE-2026-1000"})
        now, later = seed_turso.snapshots_to_seed(store)
        self.assertEqual([k for k, _ in later], ["poc_in_github"])
        self.assertNotIn("cisa_kev_v2", [k for k, _ in now], "이미 기록된 소스는 손대지 않는다")
        self.assertIn("nuclei", [k for k, _ in now])


class WeaponizableCweTests(unittest.TestCase):
    def state(self, cwe, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss=8.6):
        return {"cwe": [cwe], "cvss_vector": vector, "cvss": cvss}

    def test_cwe_288_remote_unauth_is_t2(self):
        v = risk.evaluate(self.state("CWE-288"))
        self.assertEqual(v.tier, risk.T2)
        self.assertIn("weaponizable_cwe", v.triggers)

    def test_cwe_288_needs_remote_unauth(self):
        local = risk.evaluate(self.state("CWE-288", "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertEqual(local.tier, risk.T3)

    def test_memory_corruption_stays_out(self):
        for cwe in ("CWE-122", "CWE-787", "CWE-416"):
            self.assertNotIn(cwe, risk.WEAPONIZABLE_CWE)
            self.assertEqual(risk.evaluate(self.state(cwe)).tier, risk.T3, cwe)


if __name__ == "__main__":
    unittest.main()
