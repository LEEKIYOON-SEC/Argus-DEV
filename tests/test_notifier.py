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
    def send(self, data, status=200):
        sent = Sent(status)
        with mock.patch.object(nt.requests, "post", sent), \
                mock.patch.object(nt.package_index, "fixes_for", return_value={}), \
                mock.patch.object(nt.time, "sleep"):
            ok = nt.SlackNotifier()._send_immediate(data, "KEV 등재", risk.T0)
        return ok, sent.payloads

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


class SummaryTests(unittest.TestCase):
    def test_nothing_to_report_sends_nothing(self):
        sent = Sent()
        with mock.patch.object(nt.requests, "post", sent):
            self.assertTrue(nt.SlackNotifier().send_batch_summary(tracked=0))
        self.assertEqual(sent.payloads, [])


if __name__ == "__main__":
    unittest.main()
