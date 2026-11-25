"""번역 — 실패는 표시하지 않는다 · 우선 순서 · 제목 규칙 · '제품 이름 + 취약점' 다시 만들기 (INVARIANTS '3차 개선')"""
import datetime
import json
import os
import re
import sqlite3
import sys
import time
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
for _k in ("GH_TOKEN", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"):
    os.environ.setdefault(_k, "test")  # config 가 import 때 확인한다. 테스트는 어디에도 접속하지 않는다

# libsql 은 SQLite 호환이다 — 메모리 SQLite 로 같은 SQL 을 돌린다.
if "libsql" not in sys.modules:
    _stub = types.ModuleType("libsql")
    _stub.connect = lambda database=None, auth_token=None: sqlite3.connect(":memory:", check_same_thread=False)
    sys.modules["libsql"] = _stub


def _stub_genai():
    """google-genai 가 없는 곳에서도 main 을 들여올 수 있게 빈 껍데기를 넣는다 — 모델은 아래 FakeModels 가 대신한다."""
    class _Any:
        def __init__(self, *a, **k):
            pass

        def __call__(self, *a, **k):
            return _Any()

        def __getattr__(self, name):
            return _Any()

    genai = types.ModuleType("google.genai")
    gtypes = types.ModuleType("google.genai.types")
    gtypes.__getattr__ = lambda name: _Any
    genai.Client = _Any
    genai.types = gtypes
    try:
        import google
    except ImportError:
        google = types.ModuleType("google")
        google.__path__ = []
        sys.modules["google"] = google
    google.genai = genai
    sys.modules["google.genai"] = genai
    sys.modules["google.genai.types"] = gtypes


try:
    from google import genai as _real_genai  # noqa: F401
except ImportError:
    _stub_genai()

import main  # noqa: E402
import state as pstate  # noqa: E402
import translation  # noqa: E402
from config import config  # noqa: E402
from rate_limiter import rate_limit_manager  # noqa: E402
from store.turso_store import TursoStore  # noqa: E402

RULE = translation.TITLE_RULE
_SLEEP = time.sleep
TODAY = datetime.datetime.now(datetime.timezone.utc).date()
RECENT = (TODAY - datetime.timedelta(days=3)).isoformat()


def fail(_line):
    raise RuntimeError("503 UNAVAILABLE. The model is overloaded. Please try again later.")


class FakeModels:
    """일괄 번역 지시문의 번호 줄('1. Title: …')마다 answer(줄)로 답한다. None 이면 그 항목을 답에서 뺀다."""

    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def generate_content(self, model, contents, config=None):
        self.prompts.append(contents)
        out = []
        for n, line in re.findall(r"^(\d+)\. (Title: .*)$", contents, re.MULTILINE):
            res = self.answer(line)
            if res is not None:
                out.append({"n": int(n), "title_ko": res[0], "desc_ko": res[1]})
        return types.SimpleNamespace(text=json.dumps(out, ensure_ascii=False), usage_metadata=None)

    def titles(self):
        return [t for p in self.prompts for t in re.findall(r"^\d+\. Title: (.*?) / ", p, re.MULTILINE)]


def _db():
    return TursoStore(url="libsql://test", auth_token="t")


def _add(db, cve_id, tier="T2", published="2019-05-01", **state):
    st = {"id": cve_id, "tier": tier, "published": published,
          "title": f"{cve_id} product flaw lets remote attackers run code",
          "description": "A flaw in the product lets remote attackers run arbitrary commands on the server."}
    st.update(state)
    db.upsert_cve({"id": cve_id, "last_alert_state": st, "updated_at": "2026-11-25T00:00:00+00:00"})


def _state(db, cve_id):
    return db.get_cve(cve_id)["last_alert_state"]


class TranslateRunTests(unittest.TestCase):
    """실제 translate_tracked · 실제 SQL(메모리 SQLite) · 가짜 모델."""

    def setUp(self):
        self.db = _db()
        pstate._DB_HANDLE = self.db
        patches = [mock.patch.object(rate_limit_manager, "check_and_wait", return_value=True),
                   mock.patch.object(main, "_gemini_backoff", return_value=0),
                   mock.patch.object(main.time, "sleep", return_value=None),
                   mock.patch.dict(config.PERFORMANCE, {"translation_batch_size": 1,
                                                        "translation_concurrency": 1})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(setattr, pstate, "_DB_HANDLE", None)
        self.addCleanup(setattr, main, "gemini_client", main.gemini_client)

    def use(self, answer):
        models = FakeModels(answer)
        main.gemini_client = types.SimpleNamespace(models=models)
        return models

    def run_once(self, seconds=600):
        return main.translate_tracked(self.db, time.time() + seconds)

    def test_failed_calls_leave_no_mark_and_are_sent_again(self):
        _add(self.db, "CVE-2026-0001", tier="T0")
        models = self.use(fail)
        self.assertEqual(self.run_once(), 0)
        st = _state(self.db, "CVE-2026-0001")
        for key in ("ko_tried", "ko_rule", "title_ko", "desc_ko"):
            self.assertNotIn(key, st, "서버 오류는 '시도함'이 아니다")
        sent = len(models.prompts)
        self.assertGreater(sent, 0)
        self.run_once()
        self.assertGreater(len(models.prompts), sent, "실패한 행은 다음 회차에 다시 보낸다")

    def test_rows_not_reached_before_the_deadline_are_not_marked(self):
        for i in range(3):
            _add(self.db, f"CVE-2026-000{i}", tier="T0")

        def slow(_line):
            _SLEEP(0.4)
            return "제품 원격 코드 실행 취약점", "원격 공격자가 서버에서 명령을 실행할 수 있다."

        models = self.use(slow)
        self.assertEqual(self.run_once(seconds=0.2), 1, "시간 안에 시작한 한 건만 답을 받았다")
        self.assertEqual(len(models.prompts), 1)
        states = [_state(self.db, f"CVE-2026-000{i}") for i in range(3)]
        self.assertEqual(sum("title_ko" in s for s in states), 1)
        self.assertFalse([s for s in states if "title_ko" not in s and ("ko_tried" in s or "ko_rule" in s)],
                         "시간 초과로 못 보낸 행에 표시가 남았다")

    def test_items_missing_from_the_answer_are_not_marked(self):
        _add(self.db, "CVE-2026-0003", tier="T0")
        self.use(lambda line: None)
        self.run_once()
        self.assertNotIn("ko_tried", _state(self.db, "CVE-2026-0003"))

    def test_english_answer_is_marked_once_and_not_sent_again(self):
        title = "Xen Orchestra: Empty-object login token"
        _add(self.db, "CVE-2026-0010", tier="T1", title=title)
        models = self.use(lambda line: (title, "Xen Orchestra 에서 빈 객체 토큰으로 로그인할 수 있다."))
        self.assertEqual(self.run_once(), 1, "설명은 한국어로 왔다")
        st = _state(self.db, "CVE-2026-0010")
        self.assertEqual((st.get("ko_tried"), st.get("ko_rule")), (title, RULE))
        self.assertNotIn("title_ko", st)
        self.assertEqual(st["desc_ko"], "Xen Orchestra 에서 빈 객체 토큰으로 로그인할 수 있다.")
        sent = len(models.prompts)
        self.run_once()
        self.assertEqual(len(models.prompts), sent, "같은 제목 · 같은 규칙이면 다시 보내지 않는다")

    def test_marks_left_before_this_rule_are_retried(self):
        title = "Foo Manager allows privilege escalation via crafted requests"
        _add(self.db, "CVE-2026-0011", tier="T1", title=title, ko_tried=title)
        self.use(lambda line: ("Foo Manager 권한 상승 취약점", "조작한 요청으로 권한을 높일 수 있다."))
        self.run_once()
        st = _state(self.db, "CVE-2026-0011")
        self.assertEqual(st["title_ko"], "Foo Manager 권한 상승 취약점")
        self.assertEqual(st["ko_rule"], RULE)

    def test_cve_id_title_is_written_from_the_description_and_cwe(self):
        _add(self.db, "CVE-2026-0020", tier="T0", title="CVE-2026-0020", cwe=["CWE-502"],
             description="SGLang allows unauthenticated pickle deserialization through /update_weights.",
             desc_ko="SGLang 에서 인증 없이 pickle 역직렬화가 일어난다.",
             affected=[{"vendor": "SGLang", "product": "SGLang"}])
        models = self.use(lambda line: ("SGLang 안전하지 않은 역직렬화 취약점", ""))
        self.assertEqual(self.run_once(), 1)
        st = _state(self.db, "CVE-2026-0020")
        self.assertEqual(st["title_ko"], "SGLang 안전하지 않은 역직렬화 취약점")
        self.assertEqual(st["desc_ko"], "SGLang 에서 인증 없이 pickle 역직렬화가 일어난다.", "한국어 설명은 그대로 둔다")
        prompt = models.prompts[0]
        self.assertIn("Title: (none) / Product: SGLang / CWE: CWE-502 안전하지 않은 역직렬화 / "
                      "Desc: SGLang allows unauthenticated", prompt)
        self.assertIn("Name the vulnerability type in the title", prompt)

    def test_cve_id_answer_is_not_a_title(self):
        _add(self.db, "CVE-2026-0021", tier="T0", title="CVE-2026-0021")
        self.use(lambda line: ("CVE-2026-0021", "원격 공격자가 명령을 실행할 수 있다."))
        self.run_once()
        st = _state(self.db, "CVE-2026-0021")
        self.assertNotIn("title_ko", st)
        self.assertEqual(st["ko_tried"], "CVE-2026-0021")

    def test_alert_tiers_and_recent_rows_go_before_the_id_rotation(self):
        _add(self.db, "CVE-2019-0001", tier="T2", published="2019-01-01", title="Old product flaw lets attackers in")
        _add(self.db, "CVE-2026-0100", tier="T2", published=RECENT, title="Recent product flaw lets attackers in")
        _add(self.db, "CVE-2026-0101", tier="T1", published="2018-06-01", title="Weaponized product flaw lets attackers in")
        _add(self.db, "CVE-2026-0102", tier="T0", published="2017-06-01", title="Exploited product flaw lets attackers in")
        _add(self.db, "CVE-2026-0103", tier="T3", published="2016-06-01", title="제품 원격 코드 실행 취약점",
             desc_ko="원격 공격자가 들어올 수 있다.")
        models = self.use(lambda line: ("제품 원격 코드 실행 취약점", "원격 공격자가 들어올 수 있다."))
        self.assertEqual(self.run_once(), 4)
        self.assertEqual([t.split()[0] for t in models.titles()], ["Exploited", "Weaponized", "Recent", "Old"],
                         "T0 → T1 → 최근 공개 → 나머지는 CVE 번호 순서. 우선 처리한 행은 같은 회차에 다시 보내지 않는다")

    def test_generic_titles_are_rewritten_only_with_a_type(self):
        _add(self.db, "CVE-2026-0200", tier="T0", title="Apple iOS and iPadOS vulnerability",
             title_ko="Apple iOS 및 iPadOS 취약점",
             description="Processing a maliciously crafted image may lead to arbitrary code execution.",
             desc_ko="악성 이미지를 처리하면 임의 코드가 실행될 수 있다.")
        _add(self.db, "CVE-2026-0201", tier="T2", title="Oracle WebLogic Server vulnerability",
             title_ko="Oracle WebLogic Server 취약점", desc_ko="원격 공격자가 서버를 장악할 수 있다.")
        _add(self.db, "CVE-2026-0202", tier="T2", title="WordPress Foo plugin <= 1.0 - SQL Injection",
             title_ko="WordPress Foo 플러그인 <= 1.0 - SQL Injection 취약점", desc_ko="SQL 문을 조작할 수 있다.")
        _add(self.db, "CVE-2026-0203", tier="T2", title="Apache Tomcat RCE",
             title_ko="Apache Tomcat 원격 코드 실행 취약점", desc_ko="원격 코드가 실행된다.")
        answers = {"Apple iOS and iPadOS vulnerability": ("Apple iOS 및 iPadOS 임의 코드 실행 취약점", "새 설명"),
                   "Oracle WebLogic Server vulnerability": ("Oracle WebLogic Server 취약점", "새 설명")}
        models = self.use(lambda line: answers[re.match(r"Title: (.*?) / ", line).group(1)])
        self.assertEqual(self.run_once(), 1)
        self.assertEqual(sorted(models.titles()), sorted(answers), "유형이 있는 제목은 보내지 않는다")
        st = _state(self.db, "CVE-2026-0200")
        self.assertEqual(st["title_ko"], "Apple iOS 및 iPadOS 임의 코드 실행 취약점")
        self.assertEqual(st["desc_ko"], "악성 이미지를 처리하면 임의 코드가 실행될 수 있다.", "설명은 그대로")
        st = _state(self.db, "CVE-2026-0201")
        self.assertEqual(st["title_ko"], "Oracle WebLogic Server 취약점", "유형 없는 답은 쓰지 않는다")
        self.assertEqual((st["ko_rule"], st["ko_tried"]), (RULE, "Oracle WebLogic Server vulnerability"))
        for cve_id in ("CVE-2026-0202", "CVE-2026-0203"):
            st = _state(self.db, cve_id)
            self.assertEqual(st["ko_rule"], RULE, "유형이 있는 제목은 '봄'으로만 적어 다음엔 꺼내지 않는다")
            self.assertNotIn("ko_tried", st)
        sent = len(models.prompts)
        self.run_once()
        self.assertEqual(len(models.prompts), sent, "다시 볼 제목이 남지 않았다")

    def test_regeneration_uses_only_what_is_left_and_keeps_to_its_cap(self):
        _add(self.db, "CVE-2026-0300", tier="T3", title="Ivanti Sentry vulnerability", title_ko="Ivanti Sentry 취약점",
             desc_ko="원격 공격자가 설정을 바꿀 수 있다.")
        _add(self.db, "CVE-2026-0301", tier="T0", title="Microsoft Office vulnerability", title_ko="Microsoft Office 취약점",
             desc_ko="문서를 열면 코드가 실행될 수 있다.")
        _add(self.db, "CVE-2019-0002", tier="T2", title="Widget allows attackers to read files")
        models = self.use(lambda line: ("제품 임의 파일 읽기 취약점", "파일을 읽을 수 있다."))
        with mock.patch.dict(config.PERFORMANCE, {"translation_regen_per_run": 1}), \
                mock.patch.object(main, "_translation_budget", return_value=2):
            self.run_once()
        self.assertEqual(models.titles(), ["Widget allows attackers to read files", "Microsoft Office vulnerability"],
                         "다른 번역을 먼저 하고, 남은 한도(1건) 안에서 회차당 1건 — 등급이 높은 것부터")
        self.assertEqual(_state(self.db, "CVE-2026-0300")["title_ko"], "Ivanti Sentry 취약점")
        with mock.patch.object(main, "_translation_budget", return_value=1):
            self.run_once()
        self.assertEqual(len(models.titles()), 3)
        self.assertEqual(models.titles()[-1], "Ivanti Sentry vulnerability")


class TranslationQueryTests(unittest.TestCase):
    """TursoStore 번역 쿼리 — translation.py 판정과 같은 행을 같은 순서로 꺼낸다."""

    def setUp(self):
        self.db = _db()

    def test_priority_query_takes_titles_without_hangul_in_alert_tiers_or_recent(self):
        _add(self.db, "CVE-2026-0001", tier="T2", published="2019-01-01")
        _add(self.db, "CVE-2026-0002", tier="T2", published=RECENT)
        _add(self.db, "CVE-2026-0003", tier="T1", published="2018-01-01")
        _add(self.db, "CVE-2026-0004", tier="T0", published="2017-01-01", title="CVE-2026-0004")
        _add(self.db, "CVE-2026-0005", tier="T0", published=RECENT, title_ko="제품 원격 코드 실행 취약점")
        _add(self.db, "CVE-2026-0006", tier="T3", published=RECENT)
        since = (TODAY - datetime.timedelta(days=30)).isoformat()
        rows = self.db.get_translation_priority_candidates(limit=50, since=since, rule=RULE)
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-0004", "CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0006"],
                         "T0 → T1 → T2 → T3, 오래된 T2 와 한국어 제목은 없다")
        self.assertEqual(len(self.db.get_translation_priority_candidates(limit=2, since=since, rule=RULE)), 2)

    def test_priority_query_skips_only_titles_tried_under_this_rule(self):
        t = "Widget allows attackers to read files"
        _add(self.db, "CVE-2026-0010", tier="T0", title=t, ko_tried=t, ko_rule=RULE)
        _add(self.db, "CVE-2026-0011", tier="T0", title=t, ko_tried=t)
        _add(self.db, "CVE-2026-0012", tier="T0", title=t, ko_tried="old title", ko_rule=RULE)
        rows = self.db.get_translation_priority_candidates(limit=50, since=RECENT, rule=RULE)
        self.assertEqual(sorted(r["id"] for r in rows), ["CVE-2026-0011", "CVE-2026-0012"])
        for r in rows:
            self.assertFalse(translation.tried(r["last_alert_state"]))

    def test_regen_query_takes_unchecked_korean_titles_ending_with_the_suffix(self):
        _add(self.db, "CVE-2026-0020", tier="T3", title_ko="Apple macOS 취약점")
        _add(self.db, "CVE-2026-0021", tier="T0", title_ko="Apple iOS 취약점 ")
        _add(self.db, "CVE-2026-0022", tier="T0", title_ko="Apple Safari 취약점", ko_rule=RULE)
        _add(self.db, "CVE-2026-0023", tier="T0", title_ko="Apple Safari 원격 코드 실행")
        _add(self.db, "CVE-2026-0024", tier="T0")
        rows = self.db.get_title_regen_candidates(limit=50, rule=RULE)
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-0021", "CVE-2026-0020"])

    def test_queries_return_only_what_translation_needs(self):
        _add(self.db, "CVE-2026-0030", tier="T0", cwe=["CWE-79"], analysis={"impact": "x" * 5000},
             references=["https://example.com"] * 50,
             affected=[{"vendor": "Acme", "product": "Widget"}, {"vendor": "n/a", "product": "n/a"}])
        st = self.db.get_translation_priority_candidates(limit=5, since=RECENT, rule=RULE)[0]["last_alert_state"]
        self.assertEqual(set(st), {"title", "title_ko", "description", "desc_ko", "cwe", "affected",
                                   "ko_tried", "ko_rule", "tier", "published"})
        self.assertEqual(st["cwe"], ["CWE-79"])
        self.assertEqual(st["affected"], [{"vendor": "Acme", "product": "Widget"}, {"vendor": "n/a", "product": "n/a"}])
        self.assertEqual(translation.product_of(st), "Acme Widget")


class TitleRuleTests(unittest.TestCase):

    def test_which_titles_need_work(self):
        self.assertTrue(translation.needs_title({"title": "Widget allows file reads"}))
        self.assertTrue(translation.needs_title({"title": "XSS"}), "짧은 영어 제목도 한국어가 아니다")
        self.assertTrue(translation.needs_title({"title": "CVE-2026-0001", "description": "Widget allows file reads."}))
        self.assertFalse(translation.needs_title({"title": "CVE-2026-0001", "description": "N/A"}), "지을 거리가 없다")
        self.assertTrue(translation.needs_title({"title": "N/A", "description": "Widget allows file reads."}))
        self.assertFalse(translation.needs_title({"title": "Widget", "title_ko": "Widget 파일 읽기 취약점"}))
        self.assertTrue(translation.needs_desc({"description": "Widget allows remote attackers to read files."}))
        self.assertFalse(translation.needs_desc({"description": "Widget allows x", "desc_ko": "파일을 읽을 수 있다."}))

    def test_generic_titles(self):
        for title in ("Apple iOS 및 iPadOS 취약점", "Oracle WebLogic Server 취약점", "Canonical Ubuntu 커널 취약점",
                      "WordPress Popup Maker 플러그인 취약점", "IBM Guardium Data Protection의 여러 취약점",
                      "Apache Tomcat Mapper 컴포넌트의 취약점", "BUG-000187511 - ArcGIS Server 보안 취약점",
                      "커널 취약점", "Dell Secure Connect Gateway 5.0 - 애플리케이션 취약점", "Oracle Access Manager 취약점",
                      "Perforce Helix Authentication Service 취약점", "WordPress File Upload 플러그인 취약점 "):
            self.assertTrue(translation.is_generic_title(title), title)
        for title in ("Apache Tomcat 원격 코드 실행 취약점", "WordPress Foo 플러그인 <= 1.0 - SQL Injection 취약점",
                      "DSP Service의 Use After Free 취약점", "IceWarp Mail Server의 Open redirection 취약점",
                      "WordPress Mail Mint 플러그인 <= 1.19.4 - Broken Access Control 취약점",
                      "WordPress 5.5.2 이전 버전의 XSS 취약점", "Microsoft Windows 서비스 거부 취약점",
                      "VMware vCenter Server Out-of-Bounds Write 취약점", "Apple macOS", "", None,
                      "Cisco IOS 보안 기능 우회 취약점", "WordPress Broken Link Checker 플러그인 SSRF 취약점"):
            self.assertFalse(translation.is_generic_title(title), title)

    def test_title_work(self):
        self.assertEqual(translation.title_work({"title": "Widget flaw allows reads"}), "translate")
        self.assertEqual(translation.title_work({"title": "x", "title_ko": "Apple iOS 취약점"}), "regen")
        self.assertEqual(translation.title_work({"title": "x", "title_ko": "Apple iOS 취약점", "ko_rule": RULE}), "")
        self.assertEqual(translation.title_work({"title": "x", "title_ko": "Apple iOS 권한 상승 취약점"}), "")

    def test_cwe_hint_uses_the_dashboard_names_most_specific_first(self):
        self.assertEqual(translation.cwe_hint(["CWE-79"]), "CWE-79 XSS")
        self.assertEqual(translation.cwe_hint(["CWE-200", "CWE-89"]), "CWE-89 SQL 인젝션, CWE-200 정보 노출")
        self.assertEqual(translation.cwe_hint(["NVD-CWE-noinfo", "cwe-1321", "CWE-1321"]), "CWE-1321 Prototype Pollution")
        self.assertEqual(translation.cwe_hint(["CWE-99999"]), "CWE-99999")
        self.assertEqual(translation.cwe_hint("CWE-79"), "")
        self.assertEqual(translation.cwe_hint(["CWE-79", "CWE-89", "CWE-22"], limit=2).count("CWE-"), 2)

    def test_cwe_names_fall_back_to_ids_when_the_tables_are_missing(self):
        with mock.patch.object(translation, "_JS_DIR", os.path.join(ROOT, "no-such-dir")), \
                mock.patch.object(translation, "_cwe_cache", None):
            self.assertEqual(translation.cwe_hint(["CWE-79"]), "CWE-79")

    def test_product_of(self):
        self.assertEqual(translation.product_of({"affected": [{"vendor": "Apache Software Foundation",
                                                               "product": "Apache Tomcat"}]}), "Apache Tomcat")
        self.assertEqual(translation.product_of({"affected": [{"vendor": "n/a", "product": "n/a"},
                                                              {"vendor": "Ivanti", "product": "Sentry"}]}), "Ivanti Sentry")
        self.assertEqual(translation.product_of({"affected": [None, "x"]}), "")

    def test_review(self):
        item = {"key": "Widget flaw", "need_title": True, "regen": False, "need_desc": True}
        self.assertEqual(translation.review(item, ("Widget 파일 읽기 취약점", "파일을 읽을 수 있다.")),
                         {"title_ko": "Widget 파일 읽기 취약점", "desc_ko": "파일을 읽을 수 있다.", "ko_rule": RULE})
        self.assertEqual(translation.review(item, ("Widget flaw", "")),
                         {"ko_rule": RULE, "ko_tried": "Widget flaw"})
        self.assertEqual(translation.review(item, ("Widget 취약점", "파일을 읽을 수 있다.")),
                         {"title_ko": "Widget 취약점", "desc_ko": "파일을 읽을 수 있다.", "ko_rule": RULE},
                         "번역할 때는 유형 없는 한국어 제목도 영어보다 낫다")
        regen = dict(item, regen=True, need_desc=False)
        self.assertEqual(translation.review(regen, ("Widget 취약점", "새 설명")),
                         {"ko_rule": RULE, "ko_tried": "Widget flaw"})
        self.assertEqual(translation.review(dict(item, need_title=False), ("다른 제목", "파일을 읽을 수 있다.")),
                         {"desc_ko": "파일을 읽을 수 있다.", "ko_rule": RULE}, "한국어 제목은 답으로 바꾸지 않는다")

    def test_prompts_keep_the_json_format_and_one_line_per_cve(self):
        item = translation.make_item("CVE-2026-1", {"title": "Widget\nflaw", "description": "Line one.\n\nLine two.",
                                                     "cwe": ["CWE-22"]})
        prompt = translation.batch_prompt([item, item])
        self.assertIn('[{"n":1,"title_ko":"...","desc_ko":"..."},...]', prompt)
        self.assertIn("1. Title: Widget flaw / CWE: CWE-22 Path Traversal / Desc: Line one. Line two.", prompt)
        self.assertIn("2. Title: Widget flaw", prompt)
        self.assertIn("Name the vulnerability type in the title", translation.single_prompt(item))
        self.assertIn("제목: [Korean Title]", translation.single_prompt(item))


class AnswerParsingTests(unittest.TestCase):
    """모델 응답 → 답한 항목만. 형식이 깨지면 None."""

    def setUp(self):
        for p in (mock.patch.object(rate_limit_manager, "check_and_wait", return_value=True),):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(setattr, main, "gemini_client", main.gemini_client)

    def reply(self, text):
        main.gemini_client = types.SimpleNamespace(models=types.SimpleNamespace(
            generate_content=lambda **kw: types.SimpleNamespace(text=text, usage_metadata=None)))

    def test_batch_answer_without_numbers_is_matched_by_order(self):
        chunk = [{"id": "A", "title": "a", "description": ""}, {"id": "B", "title": "b", "description": ""}]
        self.reply('```json\n[{"title_ko": "가 취약점", "desc_ko": "가"}, {"title_ko": "나 취약점", "desc_ko": "나"}]\n```')
        out, reason = main._translate_chunk_with(chunk, "p", "m", "gemma_31b", 1)
        self.assertEqual((out, reason), ({"A": ("가 취약점", "가"), "B": ("나 취약점", "나")}, "ok"))

    def test_batch_answer_keeps_only_answered_items(self):
        chunk = [{"id": "A", "title": "a", "description": ""}, {"id": "B", "title": "b", "description": ""}]
        self.reply('[{"n": 2, "title_ko": "나 취약점", "desc_ko": ""}, {"n": "x"}]')
        out, reason = main._translate_chunk_with(chunk, "p", "m", "gemma_31b", 1)
        self.assertEqual((out, reason), ({"B": ("나 취약점", "")}, "ok"))
        self.reply('[{"n": 1, "title_ko": "", "desc_ko": ""}]')
        self.assertEqual(main._translate_chunk_with(chunk, "p", "m", "gemma_31b", 1), (None, "parse"))

    def test_single_answer_lines(self):
        self.reply("**제목:** Widget 파일 읽기 취약점\n내용: 파일을 읽을 수 있다.\n")
        self.assertEqual(main._translate_one("p", "m", "gemma_31b", 1),
                         (("Widget 파일 읽기 취약점", "파일을 읽을 수 있다."), "ok"))
        self.reply("Sorry, I can't help.")
        self.assertEqual(main._translate_one("p", "m", "gemma_31b", 1), (None, "parse"))


if __name__ == "__main__":
    unittest.main()
