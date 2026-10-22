import datetime
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zipfile
from typing import Dict, List, Optional, Pattern, Set

import requests

import enrichment_sources
import pages
import rule_license
from fields import CVE_RE
from logger import logger

_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "docs", "data")
_OUT = os.path.join(_DATA, "detection-rules.json")

_TIMEOUT = 180

# 라이선스 표기는 rule_license 한 곳에서 정한다 — 항목마다 license(· YARA 는 license_url · link_only)를 적는다.
ALL_ENGINES = frozenset(("sigma", "nuclei", "splunk", "yara", "snort2", "snort3", "suricata5", "suricata7"))


MAX_PER_ENGINE = 3

# 룰마다 CVE 를 적는 방식이 다르다 — 'CVE-2026-1' 문자열만 찾으면 메시지에 번호가 없는 룰을 통째로 놓친다
# (INVARIANTS §6: Snort 3 Community 는 1,031건 중 17건만 잡혔다).
_REF_CVE = re.compile(r'reference\s*:\s*cve\s*,\s*(?:CVE-)?(\d{4}-\d{4,})', re.IGNORECASE)  # Snort · Suricata
_TAG_CVE = re.compile(r'\bcve\.(\d{4}-\d{4,})\b', re.IGNORECASE)  # Sigma 태그 cve.2021-44228
_NAME_CVE = re.compile(r'CVE_(\d{4})_(\d{4,})', re.IGNORECASE)  # YARA 룰 이름 EXPL_Log4j_CVE_2021_44228


def cves_in(text: str, *forms: Pattern) -> Set[str]:
    found = {c.upper() for c in CVE_RE.findall(text)}
    for form in forms:
        found.update("CVE-" + "-".join(m.groups()) for m in form.finditer(text))
    return found


def _add(index: Dict[str, List[Dict]], cve: str, entry: Dict) -> None:
    bucket = index.setdefault(cve.upper(), [])
    same = [e for e in bucket if e.get("engine") == entry.get("engine")]
    if any(e.get("path") == entry.get("path") for e in same):
        return
    if len(same) >= MAX_PER_ENGINE:
        return
    bucket.append(entry)


def _github_tarball(owner: str, repo: str, label: str) -> Optional[bytes]:
    token = os.environ.get("GH_TOKEN", "").strip()
    if not token:
        logger.warning(f"  ⚠️ GH_TOKEN 없음 → {label} 생략 "
                       f"(무토큰은 익명 60회/시 한도라 조용히 막힌다)")
        return None
    headers = {"User-Agent": "argus-rule-index", "Authorization": f"token {token}"}
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball"
    try:
        resp = requests.get(url, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info(f"  📥 {label} tarball {len(resp.content) / 1e6:.1f}MB")
        return resp.content
    except requests.exceptions.RequestException as e:
        logger.warning(f"  ⚠️ {label} 다운로드 실패 → 이 소스 생략: {e}")
        return None


def collect_sigma(index: Dict[str, List[Dict]]) -> Set[str]:
    data = _github_tarball("SigmaHQ", "sigma", "SigmaHQ")
    if data is None:
        return set()
    n = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not (member.isfile() and member.name.endswith(".yml")
                        and "/rules" in member.name):
                    continue
                f = tar.extractfile(member)
                if not f:
                    continue
                text = f.read().decode("utf-8", errors="ignore")
                cves = cves_in(text, _TAG_CVE)
                if not cves:
                    continue
                path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                for cve in cves:
                    _add(index, cve, rule_license.apply({
                        "engine": "sigma", "source": "SigmaHQ", "path": path,
                        "url": f"https://github.com/SigmaHQ/sigma/blob/master/{path}"}))
                    n += 1
    except tarfile.TarError as e:
        logger.warning(f"  ⚠️ SigmaHQ 압축 해제 실패: {e}")
        return set()
    logger.info(f"  ✅ SigmaHQ: {n}개 매핑")
    return {"sigma"}


def collect_splunk(index: Dict[str, List[Dict]]) -> Set[str]:
    data = _github_tarball("splunk", "security_content", "Splunk ESCU")
    if data is None:
        return set()
    n = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not (member.isfile() and "/detections/" in member.name
                        and member.name.endswith(".yml")):
                    continue
                f = tar.extractfile(member)
                if not f:
                    continue
                text = f.read().decode("utf-8", errors="ignore")
                cves = cves_in(text)
                if not cves:
                    continue
                path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                for cve in cves:
                    _add(index, cve, rule_license.apply({
                        "engine": "splunk", "source": "Splunk ESCU", "path": path,
                        "url": f"https://github.com/splunk/security_content/blob/develop/{path}"}))
                    n += 1
    except tarfile.TarError as e:
        logger.warning(f"  ⚠️ Splunk ESCU 압축 해제 실패: {e}")
        return set()
    logger.info(f"  ✅ Splunk ESCU: {n}개 매핑")
    return {"splunk"}


_YARA_FORGE = ("https://github.com/YARAHQ/yara-forge/releases/latest/download/"
               "yara-forge-rules-core.zip")


def collect_yara(index: Dict[str, List[Dict]]) -> Set[str]:
    try:
        resp = requests.get(_YARA_FORGE, timeout=_TIMEOUT,
                            headers={"User-Agent": "argus-rule-index"})
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.warning(f"  ⚠️ YARA Forge 다운로드 실패 → 생략: {e}")
        return set()
    n = 0
    try:
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in zf.namelist():
                if not name.endswith(".yar"):
                    continue
                text = zf.read(name).decode("utf-8", errors="ignore")
                for chunk in re.split(r'(?=^rule\s+\w+)', text, flags=re.M):
                    cves = cves_in(chunk, _NAME_CVE)
                    if not cves:
                        continue
                    m = re.search(r'^rule\s+(\w+)', chunk, re.M)
                    rule_name = m.group(1) if m else "?"
                    src = re.search(r'source_url\s*=\s*"([^"]+)"', chunk)
                    author = re.search(r'author\s*=\s*"([^"]+)"', chunk)
                    rule_lic = re.search(r'license_url\s*=\s*"([^"]+)"', chunk)
                    for cve in cves:
                        # 원 저장소 라이선스를 확인하지 못한 룰은 link_only — 본문을 받지도 싣지도 않는다.
                        _add(index, cve, rule_license.apply({
                            "engine": "yara", "source": "YARA Forge", "path": rule_name,
                            "url": src.group(1) if src else _YARA_FORGE,
                            "author": author.group(1) if author else "",
                            "license_url": rule_lic.group(1) if rule_lic else "",
                        }))
                        n += 1
    except zipfile.BadZipFile as e:
        logger.warning(f"  ⚠️ YARA Forge 해제 실패: {e}")
        return set()
    logger.info(f"  ✅ YARA Forge: {n}개 매핑")
    return {"yara"}


def collect_nuclei(index: Dict[str, List[Dict]]) -> Set[str]:
    idx = enrichment_sources.load_nuclei_index()
    if not enrichment_sources.nuclei_ok():
        logger.warning("  ⚠️ nuclei-templates 인덱스를 못 받음 → 생략")
        return set()
    for cve, meta in idx.items():
        path = meta.get("path", "")
        _add(index, cve, rule_license.apply({
            "engine": "nuclei", "source": "nuclei-templates", "path": path,
            "severity": meta.get("severity", ""),
            "url": enrichment_sources.nuclei_template_url(path)}))
    logger.info(f"  ✅ nuclei-templates: {len(idx)}개 매핑")
    return {"nuclei"}


_NETWORK_SOURCES = [
    ("Snort 2.9 Community", "https://www.snort.org/downloads/community/community-rules.tar.gz",
     "community.rules", "snort2"),
    ("Snort 3 Community", "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
     "snort3-community.rules", "snort3"),
    ("Snort 2.9 ET Open", "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules",
     None, "snort2"),
    ("Suricata 5 ET Open", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules",
     None, "suricata5"),
    ("Suricata 7 ET Open", "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules",
     None, "suricata7"),
]


_SID = re.compile(r'\bsid\s*:\s*(\d+)')


def _network_key(label: str, line: str) -> str:
    m = _SID.search(line)
    if m:
        return f"{label}:sid{m.group(1)}"
    return f"{label}:{hashlib.sha1(line.encode('utf-8', 'ignore')).hexdigest()[:12]}"


def collect_network(index: Dict[str, List[Dict]]) -> Set[str]:
    done: Set[str] = set()
    failed: Set[str] = set()
    for label, url, member_hint, engine in _NETWORK_SOURCES:
        et_open = rule_license.source_of({"engine": engine, "source": label}) == "et-open"
        try:
            resp = requests.get(url, timeout=_TIMEOUT,
                                headers={"User-Agent": "argus-rule-index"})
            if resp.status_code != 200:
                logger.warning(f"  ⚠️ {label} HTTP {resp.status_code} → 생략")
                failed.add(engine)
                continue
            if member_hint:
                content = None
                with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member_hint in member.name:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode("utf-8", errors="ignore")
                            break
                if content is None:
                    logger.warning(f"  ⚠️ {label} 압축 안에 {member_hint} 없음 → 생략")
                    failed.add(engine)
                    continue
            else:
                content = resp.text
        except Exception as e:
            logger.warning(f"  ⚠️ {label} 실패 → 생략: {e}")
            failed.add(engine)
            continue

        n = skipped = 0
        for line in content.splitlines():
            stripped = line.strip()
            # 주석 처리된 룰은 제조사가 기본으로 꺼 둔 룰이다 — 싣지 않는다(INVARIANTS §6).
            if not stripped or stripped.startswith("#") or "alert" not in stripped:
                continue
            # ET Open 배포본은 SID 범위마다 라이선스가 다르다 — BSD 범위 밖(GPLv2 · ET Pro)은 싣지 않는다.
            if et_open:
                m = _SID.search(stripped)
                if not rule_license.et_open_sid_ok(int(m.group(1)) if m else None):
                    skipped += 1
                    continue
            key = _network_key(label, stripped)
            for cve in cves_in(stripped, _REF_CVE):
                _add(index, cve, rule_license.apply({"engine": engine, "source": label,
                                                     "path": key, "url": "", "code": stripped}))
                n += 1
        if skipped:
            logger.info(f"  {label}: BSD 범위 밖 SID 룰 {skipped}개는 싣지 않음")
        done.add(engine)
        logger.info(f"  ✅ {label}: {n}개 매핑")
    if failed & done:
        logger.warning(f"  ⚠️ {sorted(failed & done)} 는 소스 일부만 받았다 — "
                       f"직전 인덱스에서 이월한다")
    return done - failed


def load_previous() -> Dict[str, List[Dict]]:
    try:
        payload = pages.fetch_published_json("detection-rules.json", timeout=_TIMEOUT)
        if payload is not None:
            prev = (payload or {}).get("rules") or {}
            logger.info(f"  직전 인덱스 로드(배포본): CVE {len(prev):,}건")
            return prev
    except Exception as e:
        logger.warning(f"  직전 인덱스 배포본 로드 실패({e}) → 체크아웃 사본 확인")
    try:
        with open(_OUT, encoding="utf-8") as f:
            prev = (json.load(f) or {}).get("rules") or {}
        logger.info(f"  직전 인덱스 로드(파일): CVE {len(prev):,}건")
        return prev
    except (OSError, ValueError):
        return {}


def carry_missing(index: Dict[str, List[Dict]], prev: Dict[str, List[Dict]],
                  missing: Set[str]) -> int:
    carried = 0
    for cve, entries in prev.items():
        for entry in entries or []:
            if not isinstance(entry, dict) or entry.get("engine") not in missing:
                continue
            _add(index, cve, entry)
            carried += 1
    return carried


def main() -> int:
    logger.info("=" * 60)
    logger.info("CVE ↔ 공개 탐지 룰 역인덱스 생성")
    logger.info("=" * 60)

    index: Dict[str, List[Dict]] = {}
    refreshed: Set[str] = set()
    for fn in (collect_nuclei, collect_sigma, collect_network,
               collect_splunk, collect_yara):
        try:
            refreshed |= fn(index) or set()
        except Exception as e:
            logger.error(f"{fn.__name__} 실패 → 계속 진행: {e}")

    missing = set(ALL_ENGINES) - refreshed
    if missing == ALL_ENGINES:
        logger.error("모든 소스가 실패했습니다 — 기존 파일을 덮어쓰지 않고 종료")
        return 1
    if missing:
        logger.warning(f"갱신 못 한 엔진 {sorted(missing)} — 직전 인덱스에서 이월한다 "
                       f"(못 받은 것을 '룰 없음'으로 만들지 않는다)")
        carried = carry_missing(index, load_previous(), missing)
        logger.info(f"  이월 {carried:,}개 매핑")
        if carried == 0:
            logger.error("이월할 직전 인덱스도 없습니다 — 덮어쓰지 않고 종료")
            return 1

    if not index:
        logger.error("수집된 룰이 없습니다 — 기존 파일을 덮어쓰지 않고 종료")
        return 1

    by_engine: Dict[str, int] = {}
    for entries in index.values():
        for e in entries:
            by_engine[e["engine"]] = by_engine.get(e["engine"], 0) + 1

    payload = {
        "_source": "SigmaHQ · Emerging Threats Open · Snort Community · "
                   "nuclei-templates · Splunk ESCU · YARA Forge",
        "_license": "항목마다 license 필드 참조(src/rule_license.py) — 재게시 시 출처 · author · "
                    "라이선스 고지를 함께 싣고, link_only 항목은 본문을 싣지 않는다",
        "schema": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "engines": by_engine,
        "refreshed": sorted(refreshed),
        "carried": sorted(missing),
        "rules": index,
    }
    os.makedirs(_DATA, exist_ok=True)
    tmp = _OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, _OUT)
    size = os.path.getsize(_OUT) / 1024
    logger.info(f"역인덱스 저장: {_OUT} ({size:,.0f} KB · CVE {len(index):,}건)")
    logger.info(f"엔진별: {by_engine}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
