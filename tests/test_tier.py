"""알림 등급 — Metasploit 은 T1(악용 임박), 저장 등급은 알림을 보낸 트리거를 지금 규칙으로 읽은 등급보다 높게 부르지 않는다"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import export_dashboard_data as ex  # noqa: E402
import risk  # noqa: E402


def entry(**over):
    base = {"is_kev": False, "cvss": 0, "epss": 0}
    base.update(over)
    return base


class MetasploitTierTests(unittest.TestCase):
    def test_metasploit_alone_is_t1_and_still_alerts_at_once(self):
        v = risk.evaluate({"has_metasploit_module": True})
        self.assertEqual(v.tier, risk.T1)
        self.assertIn("metasploit", v.alerting_triggers, "T1 도 즉시 알림")
        self.assertEqual(risk.evaluate({"has_metasploit_module": True, "is_kev": True}).tier, risk.T0, "KEV 가 있으면 T0")
        self.assertEqual(risk.evaluate({"has_metasploit_module": True, "is_vulncheck_kev": True}).tier, risk.T0)
        self.assertEqual(risk.evaluate({"has_metasploit_module": True, "ssvc_exploitation": "active"}).tier, risk.T0)

    def test_rows_already_alerted_for_metasploit_are_not_alerted_again(self):
        last = {"tier": risk.T0, "fired_triggers": ["metasploit"], "has_metasploit_module": True}
        d = risk.decide({"has_metasploit_module": True}, last)
        self.assertFalse(d.alert)
        self.assertEqual(d.tier, risk.T1)

    def test_reason_order_is_unchanged(self):
        d = risk.decide({"has_metasploit_module": True, "has_nuclei_template": True, "is_vulncheck_kev": True}, None)
        self.assertEqual(d.reason.split(" · "), [risk.TRIGGERS[k].label for k in ("vulncheck_kev", "metasploit", "nuclei")],
                         "근거는 T0 → Metasploit → nuclei 순서 그대로")


class StoredTierTests(unittest.TestCase):
    def tier(self, state, **e):
        return ex._tier_of(state, entry(**e))

    def test_stored_t0_from_metasploit_reads_as_t1(self):
        state = {"tier": risk.T0, "fired_triggers": ["metasploit"], "has_metasploit_module": True}
        self.assertEqual(self.tier(state), risk.T1, "다시 처리되지 않은 행도 지금 규칙으로")

    def test_observed_exploitation_stays_t0(self):
        state = {"tier": risk.T0, "fired_triggers": ["kev", "metasploit"], "is_kev": True, "has_metasploit_module": True}
        self.assertEqual(self.tier(state, is_kev=True), risk.T0)
        state = {"tier": risk.T0, "fired_triggers": ["metasploit", "vulncheck_kev"], "is_vulncheck_kev": True}
        self.assertEqual(self.tier(state), risk.T0)

    def test_history_never_raises_the_stored_tier(self):
        # KEV 에서 빠진 뒤 다시 처리돼 T1 로 저장된 행 — 발화 이력의 kev 로 T0 를 되살리지 않는다
        state = {"tier": risk.T1, "fired_triggers": ["kev", "nuclei"], "has_nuclei_template": True}
        self.assertEqual(self.tier(state), risk.T1)

    def test_never_lower_than_what_was_alerted(self):
        # EPSS 가 내려가도 알림을 보낸 등급(T1)보다 낮춰 부르지 않는다 — 예전 규칙 그대로
        state = {"tier": risk.T1, "fired_triggers": ["epss_critical"], "epss_percentile": 0.5}
        self.assertEqual(self.tier(state, epss=0.01), risk.T1)

    def test_rows_without_history_keep_the_stored_tier(self):
        self.assertEqual(self.tier({"tier": risk.T0}), risk.T0, "발화 이력이 없는 옛 행")
        state = {"tier": risk.T0, "fired_triggers": ["poc", "gone_trigger", 3]}
        self.assertEqual(self.tier(state), risk.T0, "알림 트리거가 아닌 키 · 모르는 키 · 문자열이 아닌 값은 보지 않는다")

    def test_signals_on_the_row_still_win(self):
        state = {"tier": risk.T1, "fired_triggers": ["metasploit"], "has_metasploit_module": True}
        self.assertEqual(self.tier(state, is_kev=True), risk.T0, "지금 KEV 에 있으면 T0")

    def test_retention_still_keeps_metasploit_rows(self):
        row = {"id": "CVE-2020-0001", "last_alert_state": {"tier": risk.T0, "fired_triggers": ["metasploit"],
                                                           "has_metasploit_module": True}}
        self.assertTrue(ex._is_alerting_row(row), "T0 → T1 은 알림 등급 안의 이동이라 보존 대상 그대로")
        self.assertEqual(ex._doomed([row]), [])


if __name__ == "__main__":
    unittest.main()
