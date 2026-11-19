import requests
import os
import re
import time
import threading
from typing import Dict, List, Optional

import package_index
import risk
from pages import cve_url as _cve_url
from logger import logger


class NotifierError(Exception):
    pass


# Slack 한도 — section 글 3000자 · header 150자 · 버튼 URL 3000자. 넘으면 메시지 전체가 400 으로 거부된다.
_SECTION_MAX = 2900
_HEADER_MAX = 150
_URL_MAX = 3000
_FENCE = "`" * 3


def esc(text) -> str:
    """mrkdwn 에 넣을 바깥 글(제목 · 제품 · 룰 본문) — Slack 이 요구하는 세 글자만 바꾼다."""
    return str(text if text is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def clip(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def http_url(url) -> str:
    """버튼 · 링크에 쓸 수 있는 주소만 돌려준다 — http(s) 이고 공백 · 꺾쇠 · 세로줄이 없고 한도 안."""
    url = str(url or "").strip()
    if not re.match(r"^https?://[^\s<>|]+$", url, re.I) or len(url) > _URL_MAX:
        return ""
    return url


def _rule_block(label: str, rule: Dict) -> str:
    head = f"*🟢 {esc(label)}* ({esc(rule.get('source', ''))})"
    code = str(rule.get('code') or '').strip()
    if not code:
        url = http_url(rule.get('url'))
        return f"{head}\n<{url}|원문 보기>" if url else head
    preview = code[:800] + "\n..." if len(code) > 800 else code
    preview = esc(preview).replace(_FENCE, "` ` `")  # 본문 안의 코드 울타리가 블록을 닫지 않게
    return f"{head}\n{_FENCE}{preview}{_FENCE}"


class SlackNotifier:
    RETRY_DELAYS = (2, 5, 10)


    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

        if not self.webhook_url:
            raise NotifierError("SLACK_WEBHOOK_URL이 설정되지 않음")

        self._batch_results: List[Dict] = []
        self._lock = threading.Lock()

        logger.info("Slack Notifier 초기화 완료")


    def _send_slack_with_retry(self, payload: dict, context: str = "Slack") -> bool:
        attempts = len(self.RETRY_DELAYS) + 1
        for attempt in range(attempts):
            try:
                response = requests.post(self.webhook_url, json=payload, timeout=10)
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    # 내용이 잘못된 메시지(invalid_blocks 등)는 다시 보내도 같다.
                    logger.error(f"{context} 전송 거부 (HTTP {response.status_code}): "
                                 f"{str(response.text)[:200]}")
                    return False
                response.raise_for_status()
                return True
            except requests.exceptions.RequestException as e:
                logger.warning(f"{context} 전송 실패 (시도 {attempt + 1}/{attempts}): {e}")
                if attempt == attempts - 1:
                    logger.error(f"{context} 전송 최종 실패: {e}")
                    return False
                time.sleep(self.RETRY_DELAYS[attempt])


    def collect_alert(self, cve_data: Dict, reason: str, tier: str) -> None:
        with self._lock:
            self._batch_results.append({
                "id": cve_data['id'],
                "title_ko": cve_data.get('title_ko') or cve_data.get('title') or 'N/A',
                "cvss": cve_data.get('cvss') or 0,
                "epss": cve_data.get('epss') or 0,
                "epss_percentile": cve_data.get('epss_percentile') or 0,
                "is_kev": bool(cve_data.get('is_kev')),
                "tier": tier,
                "reason": reason,
                "url": _cve_url(cve_data['id']),
            })


    def send_alert(self, cve_data: Dict, reason: str, tier: str = risk.T2) -> bool:
        self.collect_alert(cve_data, reason, tier)
        if tier in risk.ALERTING_TIERS:
            return self._send_immediate(cve_data, reason, tier)
        return True


    @staticmethod
    def _fixed_target(cve_id: str) -> str:
        pkgs = package_index.fixes_for(cve_id)
        picks = []
        for pkg, eco_map in sorted(pkgs.items()):
            for eco, fixes in sorted((eco_map or {}).items()):
                good = [f for f in (fixes or []) if f]
                if good:
                    picks.append(f"`{pkg}` {eco} → *{good[0]}*")
            if len(picks) >= 3:
                break
        if not picks:
            return ""
        more = " …" if len(pkgs) > len(picks) else ""
        return " / ".join(picks[:3]) + more


    @staticmethod
    def _attack_conditions(cve_data: Dict) -> str:
        m = risk.parse_vector(cve_data.get('cvss_vector'))
        if not m:
            return ""
        parts = []
        av = {"N": "네트워크", "A": "인접 네트워크", "L": "로컬", "P": "물리 접근"}.get(m.get("AV"))
        if av:
            parts.append(av)
        if m.get("PR") == "N":
            parts.append("인증 불필요")
        elif m.get("PR") in ("L", "H"):
            parts.append("인증 필요")
        if m.get("UI") == "N":
            parts.append("사용자 관여 없음")
        elif m.get("UI") in ("R", "A", "P"):
            parts.append("사용자 관여 필요")
        if m.get("AC") == "L" or m.get("AT") == "N":
            parts.append("조건 단순")
        return " · ".join(parts)


    @staticmethod
    def _indicators(cve_data: Dict) -> str:
        bits = []
        cvss = cve_data.get('cvss') or 0
        if cvss:
            ver = str(cve_data.get("cvss_version") or "").strip()
            bits.append(f"CVSS {cvss}" + (f" (v{ver})" if ver else ""))
        pct = cve_data.get('epss_percentile') or 0
        epss = cve_data.get('epss') or 0
        if pct:
            bits.append(f"EPSS {epss * 100:.1f}% (상위 {max(0.1, (1 - pct) * 100):.1f}%)")
        elif epss:
            bits.append(f"EPSS {epss * 100:.1f}%")
        if cve_data.get('has_metasploit_module'):
            bits.append("Metasploit 모듈")
        if cve_data.get('has_nuclei_template'):
            bits.append("nuclei 템플릿")
        if cve_data.get('ai_discovered'):
            bits.append(f"AI 발견({cve_data.get('ai_program', 'AI')})")
        if cve_data.get('has_public_exploit'):
            bits.append("ExploitDB")
        if cve_data.get('has_poc'):
            bits.append("PoC")
        return " · ".join(bits)


    def _send_immediate(self, cve_data: Dict, reason: str, tier: str) -> bool:
        try:
            cve_id = cve_data['id']
            title = cve_data.get('title_ko') or cve_data.get('title') or 'N/A'
            head = "🚨 즉시 대응" if tier == risk.T0 else "⚠️ 높음"

            lines = [f"*{esc(clip(title, 300))}*", ""]
            lines.append(f"*무엇이 바뀌었나* · {esc(reason)}")

            affected = [a for a in (cve_data.get('affected') or []) if isinstance(a, dict)]
            if affected:
                shown = []
                for a in affected[:2]:
                    vendor = str(a.get('vendor') or '').strip()
                    product = str(a.get('product') or '').strip()
                    versions = str(a.get('versions') or '').strip()
                    name = f"{vendor} {product}".strip() or product or vendor
                    if name and name.lower() not in ('unknown', 'n/a'):
                        shown.append(esc(clip(name, 120))
                                     + (f" ({esc(clip(versions, 200))})" if versions and
                                        versions != '정보 없음' else ""))
                if shown:
                    more = f" 외 {len(affected) - len(shown)}건" if len(affected) > len(shown) else ""
                    lines.append(f"*영향* · {' / '.join(shown)}{more}")

            target = self._fixed_target(cve_id)
            if target:
                lines.append(f"*패치 목표* · {target}")

            cond = self._attack_conditions(cve_data)
            if cond:
                lines.append(f"*공격 조건* · {cond}")

            ind = self._indicators(cve_data)
            if ind:
                lines.append(f"*지표* · {ind}")

            due = cve_data.get('kev_due_date')
            if due:
                lines.append(f"*CISA 조치 기한* · {esc(due)}")

            blocks = [
                {"type": "header",
                 "text": {"type": "plain_text", "text": clip(f"{head}: {cve_id}", _HEADER_MAX)}},
                {"type": "section",
                 "text": {"type": "mrkdwn", "text": clip("\n".join(lines), _SECTION_MAX)}},
            ]

            elements = []
            report_url = _cve_url(cve_data['id'])
            if report_url:
                elements.append({"type": "button", "style": "danger",
                                 "text": {"type": "plain_text", "text": "상세 리포트"},
                                 "url": report_url})
            elements.append({"type": "button",
                             "text": {"type": "plain_text", "text": "CVE 원문"},
                             "url": f"https://www.cve.org/CVERecord?id={cve_id}"})
            # 참고 링크는 CVE 레코드에 적힌 그대로다 — 주소 꼴이 아닌 것이 하나 섞여도 알림 전체가 거부된다.
            # 첫 링크가 벤더 권고라는 보장이 없어 '참고 링크'라고 적는다.
            ref = next((u for u in map(http_url, cve_data.get('references') or []) if u), "")
            if ref:
                elements.append({"type": "button",
                                 "text": {"type": "plain_text", "text": "참고 링크"},
                                 "url": ref})
            blocks.append({"type": "actions", "elements": elements[:3]})

            credits = ["출처: CISA KEV · EPSS(FIRST.org)"]
            if cve_data.get('is_vulncheck_kev'):
                credits.append("This product uses VulnCheck KEV")
            if cve_data.get('has_nuclei_template'):
                credits.append("nuclei-templates(ProjectDiscovery, MIT)")
            if cve_data.get('ai_program') == "Anthropic CVD":
                credits.append("Anthropic Disclosure Ledger")
            blocks.append({"type": "context",
                           "elements": [{"type": "mrkdwn", "text": " · ".join(credits)}]})

            ok = self._send_slack_with_retry({"blocks": blocks}, f"즉시 알림 ({cve_id})")
            if ok:
                logger.info(f"Slack 즉시 알림: {cve_id} [{tier}] {reason}")
            return ok

        except Exception as e:
            logger.error(f"Slack 즉시 알림 실패: {e}")
            return False


    def send_batch_summary(self, dashboard_url: Optional[str] = None,
                           tracked: int = 0) -> bool:
        if not self._batch_results and not tracked:
            logger.debug("배치 요약: 보낼 것 없음")
            return True

        try:
            rows = list(self._batch_results)
            t0 = [r for r in rows if r.get('tier') == risk.T0]
            t1 = [r for r in rows if r.get('tier') == risk.T1]

            lines = [f"*알림 {len(rows)}건*"]
            if t0:
                lines.append(f"• 🚨 *T0 관측된 악용:* {len(t0)}건")
            if t1:
                lines.append(f"• ⚠️ *T1 무기화 임박:* {len(t1)}건")
            if tracked:
                lines.append(f"• 📋 *T2 관찰 등록:* {tracked}건 — 대시보드에서 확인")

            blocks = [
                {"type": "header",
                 "text": {"type": "plain_text", "text": f"🛡️ Argus 요약 (알림 {len(rows)}건)"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
            ]

            if rows:
                rows.sort(key=lambda r: (risk.tier_rank(r.get('tier', risk.T2)),
                                         -(r.get('cvss') or 0)))
                items = []
                for r in rows[:8]:
                    link = f" <{r['url']}|상세>" if r.get('url') else ""
                    items.append(f"• `{r['id']}` {esc(clip(r.get('reason', ''), 160))}"
                                 f" — {esc(str(r.get('title_ko', ''))[:48])}{link}")
                if len(rows) > 8:
                    items.append(f"  … 외 {len(rows) - 8}건")
                blocks.append({"type": "divider"})
                blocks.append({"type": "section",
                               "text": {"type": "mrkdwn",
                                        "text": clip("\n".join(items), _SECTION_MAX)}})

            if dashboard_url:
                blocks.append({"type": "actions", "elements": [
                    {"type": "button", "style": "primary",
                     "text": {"type": "plain_text", "text": "📊 대시보드"},
                     "url": dashboard_url}]})

            ok = self._send_slack_with_retry({"blocks": blocks}, "배치 요약")
            if ok:
                logger.info(f"Slack 요약 전송: 알림 {len(rows)}건 · 추적 {tracked}건")
                with self._lock:
                    self._batch_results = []
            return ok

        except Exception as e:
            logger.error(f"배치 요약 생성 에러: {e}")
            return False


    def send_pipeline_warning(self, title: str, detail: str) -> bool:
        try:
            return self._send_slack_with_retry({
                "blocks": [
                    {"type": "header",
                     "text": {"type": "plain_text", "text": clip(title, _HEADER_MAX)}},
                    {"type": "section",
                     "text": {"type": "mrkdwn", "text": clip(detail, _SECTION_MAX)}},
                ]
            }, "파이프라인 경고")
        except Exception as e:
            logger.error(f"파이프라인 경고 알림 실패: {e}")
            return False


    def send_official_rule_update(self, cve_id: str, title: str, rules_info: Dict, dashboard_url: Optional[str] = None) -> bool:
        try:
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": clip(f"✅ 공식 룰 발견: {cve_id}", _HEADER_MAX)}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{esc(clip(title, 300))}*\n\n이전 리포트에 공개 탐지 룰이 없던 취약점에 대해 *공식 검증된 룰*이 새로 발견되었습니다."}},
                {"type": "divider"}
            ]

            rule_count = 0

            for key, label in (("sigma", "Sigma"), ("yara", "YARA"),
                               ("splunk", "Splunk ESCU"), ("nuclei", "nuclei")):
                rule = rules_info.get(key)
                if not rule:
                    continue
                rule_count += 1
                blocks.append({"type": "section", "text": {
                    "type": "mrkdwn", "text": _rule_block(label, rule)}})

            for net_rule in (rules_info.get('network') or []):
                if not net_rule.get('code'):
                    continue
                rule_count += 1
                blocks.append({"type": "section", "text": {
                    "type": "mrkdwn",
                    "text": _rule_block(str(net_rule.get('engine') or '').upper(),
                                        net_rule)}})

            blocks.append({"type": "divider"})
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"총 {rule_count}개 엔진의 공식 룰 발견. 위 룰을 복사하여 보안 장비에 등록하세요."}]
            })

            if dashboard_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": "대시보드에서 보기"}, "url": dashboard_url, "style": "primary"}
                    ]
                })

            success = self._send_slack_with_retry({"blocks": blocks}, f"공식 룰 알림 ({cve_id})")
            if success:
                logger.info(f"공식 룰 발견 알림 전송: {cve_id} ({rule_count}개 엔진)")
            return success

        except Exception as e:
            logger.error(f"공식 룰 알림 실패: {e}")
            return False
