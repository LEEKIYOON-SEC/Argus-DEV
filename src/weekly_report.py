import os
import datetime
import requests
from collections import Counter
from typing import Dict, List, Optional, Tuple
import pages
from fields import meaningful
from logger import logger

_API = "https://api.github.com"
_LABEL = "weekly-report"
KST = datetime.timezone(datetime.timedelta(hours=9))


def _last_iso_week(today: Optional[datetime.date] = None) -> Tuple[str, datetime.date, datetime.date]:
    today = today or datetime.datetime.now(KST).date()
    this_monday = today - datetime.timedelta(days=today.weekday())
    start = this_monday - datetime.timedelta(days=7)
    end = start + datetime.timedelta(days=6)
    iso = start.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}", start, end


def _issue_exists(repo: str, token: str, title: str) -> bool:
    resp = requests.get(
        f"{_API}/repos/{repo}/issues",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
        params={"state": "all", "labels": _LABEL, "per_page": 20},
        timeout=15,
    )
    resp.raise_for_status()
    return any((it.get("title") or "") == title for it in (resp.json() or []))


def _in_range(value, start: datetime.date, end: datetime.date) -> bool:
    try:
        day = datetime.date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return False
    return start <= day <= end


def _in_week(entry: Dict, start: datetime.date, end: datetime.date) -> bool:
    return _in_range(entry.get("date"), start, end)


def build_weekly_body(week_cves: List[Dict], week_label: str,
                      start: datetime.date, end: datetime.date) -> str:
    total = len(week_cves)
    # date 는 마지막 알림 시각(없으면 마지막 저장 시각)이다 — 처음 추적한 날이 아니라서 '신규'라고 세면
    # 레코드가 다시 저장된 옛 CVE 까지 들어간다. 이번 주에 공개된 것을 따로 센다.
    published = [c for c in week_cves if _in_range(c.get("published"), start, end)]
    critical = [c for c in week_cves if (c.get("cvss") or 0) >= 9.0]
    kev = [c for c in week_cves if c.get("is_kev")]
    weaponized = [c for c in week_cves if c.get("has_metasploit_module") or c.get("has_public_exploit")]
    poc = [c for c in week_cves if c.get("has_poc")]
    ruled = [c for c in week_cves if (c.get("rule_engines") or []) or c.get("has_official_rules")]

    prod = Counter()
    for c in week_cves:
        seen = set()
        for a in (c.get("affected") or []):
            p = meaningful(a.get("product"))
            if p and p not in seen:
                seen.add(p)
                prod[p] += 1


    def _row(c: Dict) -> str:
        sev = c.get("severity", "-")
        sig = []
        if c.get("is_kev"): sig.append("KEV")
        if c.get("has_metasploit_module"): sig.append("무기화")
        if c.get("has_public_exploit"): sig.append("EDB")
        if c.get("has_poc"): sig.append("PoC")
        title = (c.get("title") or "")[:60].replace("|", "\\|").replace("\n", " ")
        link = c["id"]
        return f"| {sev} | {link} | {c.get('cvss', 0)} | {', '.join(sig) or '–'} | {title} |"

    notable = sorted(
        week_cves,
        key=lambda c: (
            0 if c.get("is_kev") else 1,
            0 if (c.get("has_metasploit_module") or c.get("ssvc_exploitation") == "active") else 1,
            -(c.get("cvss") or 0),
        ),
    )[:10]

    base = pages.base_url()
    dash = f"{base}cve.html" if base else ""

    lines = [
        f"# 📅 Argus 주간 리포트 — {week_label}",
        "",
        f"> **대상 기간:** {start:%Y-%m-%d}(월) ~ {end:%Y-%m-%d}(일)",
        "",
        "## 📊 이번 주 탐지 요약",
        "",
        "| 항목 | 건수 |",
        "| :--- | ---: |",
        f"| 이번 주에 알렸거나 갱신된 추적 CVE | **{total}** |",
        f"| 그중 이번 주에 공개된 CVE | {len(published)} |",
        f"| 🔴 Critical (CVSS 9+) | {len(critical)} |",
        f"| 🚨 CISA KEV 등재 | {len(kev)} |",
        f"| 🧨 무기화 (Metasploit·ExploitDB) | {len(weaponized)} |",
        f"| 🔬 PoC 공개 | {len(poc)} |",
        f"| 🛡️ 공개 탐지 룰 확보 | {len(ruled)} |",
        "",
    ]

    if prod:
        lines += ["## 📦 이번 주 영향 제품 TOP", "", "| 제품 | 건수 |", "| :--- | ---: |"]
        lines += [f"| {p} | {n} |" for p, n in prod.most_common(5)]
        lines.append("")

    if notable:
        lines += [
            "## 🎯 주목할 CVE",
            "",
            "| 심각도 | CVE | CVSS | 신호 | 제목 |",
            "| :--- | :--- | ---: | :--- | :--- |",
        ]
        lines += [_row(c) for c in notable]
        lines.append("")

    if dash:
        lines += [f"🔗 [전체 대시보드에서 보기]({dash})", ""]

    lines += [
        "---",
        "<sub>이 리포트는 대시보드 데이터를 그대로 집계해 자동 생성됩니다(추가 AI·DB 비용 없음). "
        "데이터 출처와 라이선스는 각 CVE 상세 리포트의 각주를 참조하세요. "
        "분석·위험도 분류는 참고용입니다.</sub>",
    ]
    return "\n".join(lines)


def publish_weekly_report(cve_data: List[Dict],
                          repo: Optional[str] = None, token: Optional[str] = None) -> Optional[str]:
    repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
    token = token or os.environ.get("GH_TOKEN", "")
    if not repo or not token:
        print("  주간 리포트 생략 (GITHUB_REPOSITORY/GH_TOKEN 미설정)", flush=True)
        return None

    week_label, start, end = _last_iso_week()
    title = f"[Argus 주간 리포트] {week_label} ({start:%m/%d}~{end:%m/%d})"

    if _issue_exists(repo, token, title):
        print(f"  {week_label} 리포트 이미 발행됨 — 건너뜀", flush=True)
        return None

    week_cves = [c for c in cve_data if _in_week(c, start, end)]
    if not week_cves:
        print(f"  {week_label} 기간 데이터 없음 — 발행 생략", flush=True)
        return None

    body = build_weekly_body(week_cves, week_label, start, end)
    resp = requests.post(
        f"{_API}/repos/{repo}/issues",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
        json={"title": title, "body": body, "labels": ["security", _LABEL]},
        timeout=15,
    )
    resp.raise_for_status()
    url = resp.json().get("html_url")
    print(f"  📅 주간 리포트 발행: {url} ({len(week_cves)}건 집계)", flush=True)
    logger.info(f"주간 리포트 발행: {url}")
    return url
