"""Slack 알림 — 길이 한도 · 바깥 글 이스케이프 · 링크 검증 · 거부된 메시지는 다시 보내지 않는다"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
for _k in ("SLACK_WEBHOOK_URL", "GEMINI_API_KEY", "TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"):
    os.environ.setdefault(_k, "test")  # 테스트는 어디에도 접속하지 않는다

import notifier as nt  # noqa: E402
import risk  # noqa: E402


def cve(**over):
    base = {"id": "CVE-2026-0001", "title": "Acme <b>Widget</b> & co RCE", "cvss": 9.8, "is_kev": True,
            "affected": [{"vendor": "Acme", "product": "Widget", "versions": "1.0 이전"}],
            "references": ["not a url", "ftp://x.example/a", "https://acme.example/advisory"]}
    base.update(over)
    return base


class Sent:
    def __init__(self, status=200):
        self.payloads = []
        self.status = status

    def __call__(self, url, json=None, timeout=None):
        self.payloads.append(json)
        resp = mock.Mock(status_code=self.status, text="invalid_blocks")
        resp.raise_for_status = mock.Mock()
        return resp


class ImmediateAlertTests(unittest.TestCase):
    def send(self, data, status=200, tier=risk.T0):
        sent = Sent(status)
        with mock.patch.object(nt.requests, "post", sent), \
                mock.patch.object(nt.package_index, "fixes_for", return_value={}), \
                mock.patch.object(nt.time, "sleep"):
            ok = nt.SlackNotifier()._send_immediate(data, "KEV 등재", tier)
        return ok, sent.payloads

    def test_header_names_the_tier(self):
        _, (t0,) = self.send(cve())
        _, (t1,) = self.send(cve(is_kev=False, has_metasploit_module=True), tier=risk.T1)
        self.assertEqual(t0["blocks"][0]["text"]["text"], "🚨 즉시 대응: CVE-2026-0001")
        self.assertEqual(t1["blocks"][0]["text"]["text"], "⚠️ 악용 임박: CVE-2026-0001", "T1 은 등급 이름으로")

    def test_outside_text_is_escaped(self):
        ok, (payload,) = self.send(cve())
        text = payload["blocks"][1]["text"]["text"]
        self.assertTrue(ok)
        self.assertIn("Acme &lt;b&gt;Widget&lt;/b&gt; &amp; co RCE", text)
        self.assertNotIn("<b>", text)

    def test_section_stays_under_the_slack_limit(self):
        long = cve(affected=[{"vendor": "Acme", "product": "Widget", "versions": "1.0, " * 2000}] * 2,
                   title="T" * 5000)
        _, (payload,) = self.send(long)
        self.assertLessEqual(len(payload["blocks"][1]["text"]["text"]), 3000)
        self.assertLessEqual(len(payload["blocks"][0]["text"]["text"]), 150)

    def test_reference_button_takes_the_first_usable_link(self):
        _, (payload,) = self.send(cve())
        buttons = payload["blocks"][2]["elements"]
        self.assertEqual(buttons[-1]["url"], "https://acme.example/advisory")
        _, (payload,) = self.send(cve(references=["javascript:alert(1)", "https://a.example/x y"]))
        self.assertEqual([b["text"]["text"] for b in payload["blocks"][2]["elements"]], ["CVE 원문"], "쓸 수 있는 주소가 없으면 버튼을 넣지 않는다 (테스트 환경에는 대시보드 주소가 없다)")

    def test_rejected_message_is_not_retried(self):
        ok, payloads = self.send(cve(), status=400)
        self.assertFalse(ok)
        self.assertEqual(len(payloads), 1, "내용이 잘못된 메시지는 다시 보내도 같다")

    def test_rate_limit_is_retried(self):
        calls = []

        def post(url, json=None, timeout=None):
            calls.append(json)
            resp = mock.Mock(status_code=429 if len(calls) == 1 else 200, text="")
            resp.raise_for_status = mock.Mock(
                side_effect=nt.requests.exceptions.HTTPError("429") if len(calls) == 1 else None)
            return resp

        with mock.patch.object(nt.requests, "post", post), mock.patch.object(nt.time, "sleep"):
            self.assertTrue(nt.SlackNotifier()._send_slack_with_retry({"blocks": []}))
        self.assertEqual(len(calls), 2)


class HelperTests(unittest.TestCase):
    def test_http_url(self):
        self.assertEqual(nt.http_url(" https://a.example/x?y=1 "), "https://a.example/x?y=1")
        for bad in ("", None, "ftp://a.example", "https://a.example/x y", "https://a.example/<x>",
                    "https://a.example/a|b", "https://a.example/" + "a" * 3000):
            self.assertEqual(nt.http_url(bad), "", bad)

    def test_clip(self):
        self.assertEqual(nt.clip("abc", 3), "abc")
        self.assertEqual(nt.clip("abcdef", 4), "abc…")

    def test_rule_block_escapes_code_and_keeps_the_fence(self):
        block = nt._rule_block("Sigma", {"source": "SigmaHQ", "code": "a < b && ```x```"})
        self.assertIn("a &lt; b &amp;&amp; ` ` `x` ` `", block)
        self.assertEqual(block.count("```"), 2)
        self.assertNotIn("원문 보기", nt._rule_block("YARA", {"source": "s", "url": "javascript:1"}))


class OfficialRuleTests(unittest.TestCase):
    """'공식 룰 발견' — 탐지 룰만 센다. 함께 찾은 nuclei 는 점검 템플릿으로 이름을 달리해 덧붙인다"""

    def test_nuclei_is_labelled_as_a_check_template_and_not_counted(self):
        sent = Sent()
        rules = {"sigma": {"source": "SigmaHQ", "code": "title: x"},
                 "network": [{"engine": "snort3", "source": "Snort 3 Community", "code": "alert http any any -> any any (sid:1;)"}],
                 "nuclei": {"source": "nuclei-templates", "link_only": True,
                            "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/x.yaml"}}
        with mock.patch.object(nt.requests, "post", sent):
            self.assertTrue(nt.SlackNotifier().send_official_rule_update("CVE-2026-0001", "제목", rules))
        texts = [b["text"]["text"] for b in sent.payloads[0]["blocks"] if b.get("type") == "section"]
        texts += [e["text"] for b in sent.payloads[0]["blocks"] if b.get("type") == "context" for e in b["elements"]]
        joined = "\n".join(texts)
        self.assertIn("*🟢 Sigma* (SigmaHQ)", joined)
        self.assertIn("*🟢 SNORT3* (Snort 3 Community)", joined)
        self.assertIn("*🟢 nuclei 점검 템플릿 (탐지 룰 아님)* (nuclei-templates)", joined)
        self.assertIn("총 2개 엔진의 공식 룰 발견", joined, "nuclei 는 세지 않는다")
        self.assertLess(joined.index("SNORT3"), joined.index("nuclei 점검 템플릿"), "탐지 룰 다음에")


class SummaryTests(unittest.TestCase):
    def test_nothing_to_report_sends_nothing(self):
        sent = Sent()
        with mock.patch.object(nt.requests, "post", sent):
            self.assertTrue(nt.SlackNotifier().send_batch_summary(tracked=0))
        self.assertEqual(sent.payloads, [])

    def test_counts_use_the_tier_names(self):
        sent = Sent()
        n = nt.SlackNotifier()
        n.collect_alert(cve(), "KEV 등재", risk.T0)
        n.collect_alert(cve(id="CVE-2026-0002", is_kev=False), "Metasploit 모듈 공개", risk.T1)
        with mock.patch.object(nt.requests, "post", sent):
            self.assertTrue(n.send_batch_summary(tracked=0))
        text = sent.payloads[0]["blocks"][1]["text"]["text"]
        self.assertIn("• 🚨 *T0 관측된 악용:* 1건", text)
        self.assertIn("• ⚠️ *T1 악용 임박:* 1건", text)


if __name__ == "__main__":
    unittest.main()
