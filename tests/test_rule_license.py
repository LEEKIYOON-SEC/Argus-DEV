import copy
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import build_rule_index as bri  # noqa: E402
import export_dashboard_data as ex  # noqa: E402
import rule_license as rl  # noqa: E402
import rule_manager as rm  # noqa: E402

SIG_BASE = "https://github.com/Neo23x0/signature-base/blob/94a1c48d/LICENSE"


class TermsTests(unittest.TestCase):
    """룰마다 적을 라이선스 — 화면(docs/js/context.js ruleTerms)과 같은 표기"""

    def test_network_rules_follow_their_source(self):
        # 옛 색인은 ET Open 을 MIT 로, Snort Community 를 'MIT / GPLv2' 로 적었다.
        for source, engine in (("Snort 2.9 ET Open", "snort2"), ("Suricata 5 ET Open", "suricata5"),
                               ("Suricata 7 ET Open", "suricata7")):
            t = rl.terms({"engine": engine, "source": source, "license": "MIT"})
            self.assertEqual(t["license"], "BSD", source)
            self.assertEqual(t["license_url"], "https://rules.emergingthreats.net/open/suricata-7.0/LICENSE")
            self.assertFalse(t["link_only"])
        for source, engine in (("Snort 2.9 Community", "snort2"), ("Snort 3 Community", "snort3")):
            t = rl.terms({"engine": engine, "source": source, "license": "MIT / GPLv2(레거시 SID 1–3464)"})
            self.assertEqual(t["license"], "GPLv2", source)
            self.assertEqual(t["license_url"], "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html")

    def test_fixed_sources(self):
        self.assertEqual(rl.terms({"engine": "sigma"})["license"], "DRL 1.1")
        self.assertEqual(rl.terms({"engine": "sigma"})["license_url"], "https://github.com/SigmaHQ/Detection-Rule-License")
        self.assertEqual(rl.terms({"engine": "splunk"})["license"], "Apache-2.0")
        self.assertTrue(rl.terms({"engine": "nuclei"})["link_only"], "점검 템플릿은 링크만")

    def test_yara_license_comes_from_the_origin_repository(self):
        # 저작권 문구는 BSD · MIT 저장소의 LICENSE 에 적힌 그대로 (DRL 은 작성자 표기, craiu 는 문구 자체가 없음)
        cases = {
            SIG_BASE: ("DRL 1.1", ""),
            "https://github.com/SEKOIA-IO/Community/blob/fa3a/LICENSE.md": ("DRL 1.1", ""),
            "https://github.com/ditekshen/detection/blob/e76c/LICENSE.txt":
                ("BSD-2-Clause", "Copyright 2021 by ditekSHen (https://github.com/ditekshen/detection)."),
            "https://github.com/volexity/threat-intel/blob/a7ea/LICENSE.txt": ("BSD-2-Clause", "Copyright 2022 by Volexity, Inc."),
            "https://github.com/elceef/yara-rulz/blob/5683/LICENSE": ("MIT", "Copyright (c) 2022 Marcin Ulikowski"),
            "https://github.com/craiu/yararules/blob/23cf/LICENSE": ("GPL-3.0", ""),
        }
        for url, (name, holder) in cases.items():
            t = rl.terms({"engine": "yara", "license_url": url})
            self.assertEqual((t["license"], t["holder"], t["link_only"]), (name, holder, False), url)

    def test_yara_without_a_known_license_is_link_only(self):
        # 실측: fboldewin · StrangerealIntel · sbousseaden · SIFalcon 저장소에는 LICENSE 파일이 없다(license_url 'N/A').
        for lic_url in ("N/A", "", None):
            t = rl.terms({"engine": "yara", "license_url": lic_url})
            self.assertEqual(t, {"license": "", "license_url": "", "holder": "", "link_only": True})
        unknown = rl.terms({"engine": "yara", "license_url": "https://github.com/someone/rules/blob/x/LICENSE"})
        self.assertEqual((unknown["license"], unknown["link_only"]), ("", True),
                         "LICENSE 가 있어도 종류를 확인하지 않은 저장소는 본문을 싣지 않는다")

    def test_repo_of_tolerates_double_slash(self):
        self.assertEqual(rl.repo_of("https://github.com/fboldewin/YARA-rules//blob/54e9/x.yar"), "fboldewin/yara-rules")

    def test_et_open_sid_ranges(self):
        self.assertTrue(rl.et_open_sid_ok(2000000))
        self.assertTrue(rl.et_open_sid_ok(2799999))
        for sid in (None, 1, 3464, 2800000, 2900000, 100000000):
            self.assertFalse(rl.et_open_sid_ok(sid), sid)


class ApplyTests(unittest.TestCase):
    def test_apply_is_idempotent_and_drops_body_when_link_only(self):
        rule = {"engine": "yara", "source": "YARA Forge", "license": "룰별 상이", "note": "x",
                "license_url": "N/A", "url": "https://github.com/fboldewin/YARA-rules//blob/54e9/x.yar",
                "author": "Frank", "code": "rule leak {}"}
        once = rl.apply(rule)
        self.assertNotIn("code", once)
        self.assertNotIn("note", once)
        self.assertTrue(once["link_only"])
        self.assertEqual(once["author"], "Frank")
        self.assertEqual(rl.apply(once), once)
        self.assertEqual(rule["code"], "rule leak {}", "원본은 바꾸지 않는다")

    def test_apply_keeps_body_and_per_rule_license_url_only_for_yara(self):
        yara = rl.apply({"engine": "yara", "license_url": SIG_BASE, "code": "rule ok {}"})
        self.assertEqual((yara["license"], yara["license_url"], yara["code"]), ("DRL 1.1", SIG_BASE, "rule ok {}"))
        self.assertNotIn("link_only", yara)
        self.assertNotIn("holder", yara, "DRL 저장소는 저작권 문구 대신 작성자 표기")
        bsd = rl.apply({"engine": "yara", "license_url": "https://github.com/volexity/threat-intel/blob/a7ea/LICENSE.txt",
                        "code": "rule v {}"})
        self.assertEqual((bsd["license"], bsd["holder"]), ("BSD-2-Clause", "Copyright 2022 by Volexity, Inc."))
        self.assertEqual(rl.apply(bsd), bsd, "여러 번 적용해도 같다")
        gone = rl.apply(dict(bsd, license_url="N/A"))
        self.assertNotIn("holder", gone, "본문을 못 싣게 되면 저작권 문구도 남기지 않는다")
        net = rl.apply({"engine": "snort2", "source": "Snort 2.9 ET Open", "license": "MIT", "license_url": "",
                        "code": "alert"})
        self.assertEqual(net["license"], "BSD")
        self.assertNotIn("license_url", net, "출처가 정해진 룰의 링크는 화면이 안다")
        self.assertEqual(net["code"], "alert")


class ExportTests(unittest.TestCase):
    """증분 export 는 이월된 행도 다시 쓴다 — 옛 표기와 싣지 말아야 할 본문이 남지 않는다"""

    def rows(self):
        return [
            {"id": "CVE-2023-23397", "rules": {"yara": {
                "engine": "yara", "source": "YARA Forge", "license": "룰별 상이", "license_url": "N/A",
                "url": "https://github.com/fboldewin/YARA-rules//blob/54e9/x.yar", "code": "rule leak {}"}}},
            {"id": "CVE-2019-0708", "rules": {"network": [
                {"engine": "snort2", "source": "Snort 2.9 ET Open", "license": "MIT / GPLv2(레거시 SID 1–3464)",
                 "note": "Emerging Threats Open / Snort Community", "license_url": "", "code": "alert a"},
                {"engine": "snort2", "source": "Snort 2.9 Community", "license": "MIT / GPLv2(레거시 SID 1–3464)",
                 "license_url": "", "code": "alert b"}],
                "nuclei": {"engine": "nuclei", "source": "nuclei-templates", "license": "MIT", "url": "https://x"}}},
            {"id": "CVE-2026-0001"},
        ]

    def test_normalize_rules_fixes_carried_rows(self):
        rows = self.rows()
        self.assertEqual(ex.normalize_rules(rows), 2)
        yara = rows[0]["rules"]["yara"]
        self.assertNotIn("code", yara)
        self.assertTrue(yara["link_only"])
        net = rows[1]["rules"]["network"]
        self.assertEqual([r["license"] for r in net], ["BSD", "GPLv2"])
        self.assertEqual([r["code"] for r in net], ["alert a", "alert b"])
        self.assertTrue(all("note" not in r for r in net))
        self.assertTrue(rows[1]["rules"]["nuclei"]["link_only"])
        again = copy.deepcopy(rows)
        self.assertEqual(ex.normalize_rules(again), 0, "두 번째 적용은 바꾸는 것이 없다")
        self.assertEqual(again, rows)


class RuleManagerTests(unittest.TestCase):
    """스냅샷 — 본문을 실을 수 없는 룰은 원문을 받지 않고, 실을 수 있는 룰이 앞선다"""

    def test_link_only_yara_is_not_fetched_and_licensed_one_wins(self):
        index = {"CVE-2026-0002": [
            {"engine": "yara", "source": "YARA Forge", "license_url": "N/A",
             "url": "https://github.com/sbousseaden/YaraHunts//blob/71b2/a.yar", "author": "S"},
            {"engine": "yara", "source": "YARA Forge", "license_url": SIG_BASE,
             "url": "https://github.com/Neo23x0/signature-base/blob/94a1/b.yar", "author": "F"},
        ]}
        fetched = []

        def fake_fetch(entry):
            fetched.append(entry["url"])
            return "rule ok {}"

        with mock.patch.object(rm, "_index", return_value=index), mock.patch.object(rm, "_fetch_text", fake_fetch):
            rules, complete = rm.RuleManager().search_public_only("CVE-2026-0002")
        self.assertTrue(complete)
        self.assertEqual(fetched, ["https://github.com/Neo23x0/signature-base/blob/94a1/b.yar"])
        self.assertEqual((rules["yara"]["license"], rules["yara"]["code"]), ("DRL 1.1", "rule ok {}"))

    def test_only_link_only_yara_is_kept_as_link(self):
        index = {"CVE-2026-0003": [{"engine": "yara", "source": "YARA Forge", "license_url": "N/A",
                                    "url": "https://github.com/SIFalcon/Detection/blob/2d7c/a.yar"}]}
        with mock.patch.object(rm, "_index", return_value=index), \
                mock.patch.object(rm, "_fetch_text", side_effect=AssertionError("받지 않는다")):
            rules, complete = rm.RuleManager().search_public_only("CVE-2026-0003")
        self.assertTrue(complete)
        self.assertTrue(rules["yara"]["link_only"])
        self.assertNotIn("code", rules["yara"])

    def test_network_rules_take_one_per_engine_first(self):
        # 색인은 Snort Community 를 ET Open 앞에 둔다. 앞에서부터 3건을 고르던 때는 같은 엔진이 자리를 채워, 2026-10-22 운영
        # 데이터로 이미 룰이 있던 CVE 를 다시 만들면 113곳에서 화면의 엔진(주로 Suricata)이 빠졌다.
        def net(engine, source, sid):
            return {"engine": engine, "source": source, "url": "", "path": f"{source}:sid{sid}",
                    "code": f'alert tcp any any -> any any (msg:"x"; sid:{sid}; rev:1;)'}

        index = {
            "CVE-2026-109618": [net("snort2", "Snort 2.9 Community", 67359), net("snort2", "Snort 2.9 Community", 67375),
                                net("snort3", "Snort 3 Community", 67359), net("snort3", "Snort 3 Community", 67375)],
            "CVE-2009-1151": [net("snort3", "Snort 3 Community", 2281), net("snort2", "Snort 2.9 ET Open", 2010902),
                              net("snort2", "Snort 2.9 ET Open", 2010903), net("suricata5", "Suricata 5 ET Open", 2010902),
                              net("suricata7", "Suricata 7 ET Open", 2010902)],
            "CVE-2010-3333": [net("snort2", "Snort 2.9 ET Open", sid) for sid in (2020699, 2016932, 2016933)]
                             + [net("suricata5", "Suricata 5 ET Open", 2020699)],
            "CVE-2016-0001": [net("snort2", "Snort 2.9 ET Open", sid) for sid in (2000001, 2000002, 2000003, 2000004)],
        }
        with mock.patch.object(rm, "_index", return_value=index), \
                mock.patch.object(rm.requests, "get", side_effect=AssertionError("본문은 색인에 있다")):
            picked = {cve: [rm.rule_key(r) for r in rm.RuleManager().search_public_only(cve)[0]["network"]]
                      for cve in index}
        self.assertEqual(picked["CVE-2026-109618"], [("snort2", "Snort 2.9 Community:sid67359"),
                                                     ("snort3", "Snort 3 Community:sid67359"),
                                                     ("snort2", "Snort 2.9 Community:sid67375")])
        self.assertEqual([e for e, _ in picked["CVE-2009-1151"]], ["snort3", "snort2", "suricata5", "suricata7"],
                         "엔진이 넷이면 넷 다 싣는다")
        self.assertEqual(picked["CVE-2010-3333"], [("snort2", "Snort 2.9 ET Open:sid2020699"),
                                                   ("suricata5", "Suricata 5 ET Open:sid2020699"),
                                                   ("snort2", "Snort 2.9 ET Open:sid2016932")])
        self.assertEqual(len(picked["CVE-2016-0001"]), 3, "엔진이 하나면 앞에서부터 3건")


class RuleIndexTests(unittest.TestCase):
    """색인 — ET Open 은 BSD 범위 SID 만, 라이선스는 출처대로"""

    def test_et_open_keeps_only_bsd_range(self):
        body = "\n".join([
            '# alert tcp any any -> any any (msg:"commented CVE-2026-1111"; sid:2000001;)',
            'alert tcp any any -> any any (msg:"bsd CVE-2026-1111"; sid:2034647; rev:1;)',
            'alert tcp any any -> any any (msg:"gpl CVE-2026-2222"; sid:2466; rev:1;)',
            'alert tcp any any -> any any (msg:"pro CVE-2026-3333"; sid:2850000; rev:1;)',
        ])
        resp = mock.Mock(status_code=200, text=body)
        sources = [("Suricata 7 ET Open", "https://example/emerging-all.rules", None, "suricata7")]
        index = {}
        with mock.patch.object(bri, "_NETWORK_SOURCES", sources), mock.patch.object(bri.requests, "get", return_value=resp):
            done = bri.collect_network(index)
        self.assertEqual(done, {"suricata7"})
        self.assertEqual(sorted(index), ["CVE-2026-1111"])
        entry = index["CVE-2026-1111"][0]
        self.assertEqual((entry["license"], entry["source"]), ("BSD", "Suricata 7 ET Open"))
        self.assertIn("sid:2034647", entry["code"])

    def test_reference_cve_without_cve_in_message_is_indexed(self):
        # 실측 2026-10-22: snort3-community.rules 의 sid 67359 는 메시지에 CVE 번호가 없고 reference 로만 적는다.
        body = "\n".join([
            'alert http $EXTERNAL_NET any -> $HOME_NET any ( msg:"SERVER-WEBAPP PHP serialized integer key collision '
            'remote code execution attempt"; flow:to_server,established; http_client_body; content:"i:4294967296|3B|"; '
            'metadata:policy balanced-ips drop,ruleset community; reference:cve,2026-109618; reference:cve,2026-109619; '
            'classtype:web-application-attack; gid:1; sid:67359; rev:2; )',
            '# alert tcp any any -> any any ( msg:"disabled"; reference:cve,2026-5555; gid:1; sid:60001; rev:1; )',
        ])
        resp = mock.Mock(status_code=200, text=body)
        sources = [("Snort 3 Community", "https://example/snort3-community.rules", None, "snort3")]
        index = {}
        with mock.patch.object(bri, "_NETWORK_SOURCES", sources), mock.patch.object(bri.requests, "get", return_value=resp):
            done = bri.collect_network(index)
        self.assertEqual(done, {"snort3"})
        self.assertEqual(sorted(index), ["CVE-2026-109618", "CVE-2026-109619"], "주석 처리된(꺼진) 룰은 싣지 않는다")
        entry = index["CVE-2026-109618"][0]
        self.assertEqual((entry["engine"], entry["license"], entry["path"]), ("snort3", "GPLv2", "Snort 3 Community:sid67359"))
        self.assertIn("sid:67359", entry["code"])

    def test_cves_in_reads_each_source_form(self):
        self.assertEqual(bri.cves_in("reference:cve,2021-44228; reference: CVE , CVE-2014-6271;", bri._REF_CVE),
                         {"CVE-2021-44228", "CVE-2014-6271"})
        self.assertEqual(bri.cves_in("tags:\n  - attack.t1190\n  - cve.2021-44228\n", bri._TAG_CVE), {"CVE-2021-44228"})
        self.assertEqual(bri.cves_in("rule EXPL_Log4j_CVE_2021_44228_JAVA_Exception {", bri._NAME_CVE), {"CVE-2021-44228"})
        self.assertEqual(bri.cves_in("title: Exploit CVE-2023-23397 (Outlook)"), {"CVE-2023-23397"})
        self.assertEqual(bri.cves_in("reference:cve,2021; cve.21-1; CVE_2021_12", bri._REF_CVE, bri._TAG_CVE, bri._NAME_CVE),
                         set(), "번호가 덜 적힌 것은 CVE 로 보지 않는다")
        self.assertEqual(bri.cves_in("reference:cve,2021-44228;"), set(), "형식을 넘기지 않으면 CVE- 문자열만 본다")


if __name__ == "__main__":
    unittest.main()
