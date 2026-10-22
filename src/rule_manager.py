import re
import json
import os
import threading
from typing import Dict, List, Optional, Tuple

import requests

import pages
import rule_license
from logger import logger

_INDEX_LOCK = threading.Lock()
_INDEX: Optional[Dict[str, List[Dict]]] = None
_INDEX_OK = False
# 색인을 만든 시각과 직전 색인보다 룰이 늘어난 CVE (build_rule_index.grown_since) — 옛 색인에는 없다.
_META: Dict = {"generated_at": "", "grown": []}

_LOCAL = os.path.join(pages.DATA_DIR, "detection-rules.json")

_MAX_RULE_CHARS = 6000


def _index() -> Dict[str, List[Dict]]:
    global _INDEX, _INDEX_OK
    if _INDEX is not None:
        return _INDEX
    with _INDEX_LOCK:
        if _INDEX is None:
            _INDEX, _INDEX_OK = _load()
    return _INDEX


def index_ok() -> bool:
    _index()
    return _INDEX_OK


def grown() -> Tuple[List[str], str]:
    _index()
    return list(_META["grown"]), _META["generated_at"]


def _keep_meta(payload: Dict) -> None:
    ids = payload.get("grown")
    _META["grown"] = [str(c).upper() for c in ids] if isinstance(ids, list) else []
    _META["generated_at"] = str(payload.get("generated_at") or "")


def _load() -> Tuple[Dict[str, List[Dict]], bool]:
    try:
        payload = pages.fetch_published_json("detection-rules.json", timeout=120)
        if payload is not None:
            idx = (payload or {}).get("rules") or {}
            _keep_meta(payload or {})
            logger.info(f"탐지 룰 인덱스 로드(배포본): {len(idx):,}건")
            return idx, True
    except Exception as e:
        logger.warning(f"탐지 룰 인덱스 배포본 로드 실패({e}) → 체크아웃 사본 확인")
    try:
        with open(_LOCAL, encoding="utf-8") as f:
            payload = json.load(f) or {}
        if not isinstance(payload, dict):
            payload = {}
        idx = payload.get("rules") or {}
        _keep_meta(payload)
        logger.info(f"탐지 룰 인덱스 로드(파일): {len(idx):,}건")
        return idx, True
    except (OSError, ValueError):
        logger.warning("탐지 룰 인덱스를 받지 못했다 — '룰 없음'으로 기록하지 않는다")
        return {}, False


LINK_ONLY_ENGINES = rule_license.LINK_ONLY_ENGINES

_AUTHOR_RE = re.compile(r"^[ \t]{0,4}author[ \t]*:[ \t]*(\S.*?)[ \t]*$", re.M)


def author_of(code: str) -> str:
    m = _AUTHOR_RE.search(code or "")
    if not m:
        return ""
    name = m.group(1).strip().strip("'\"")
    return "" if name in ("|", ">", "") else name[:120]


def _fetch_text(entry: Dict) -> Optional[str]:
    if entry.get("code"):
        return entry["code"]
    url = entry.get("url") or ""
    raw = (url.replace("https://github.com/", "https://raw.githubusercontent.com/")
              .replace("/blob/", "/"))
    if not raw.startswith("http"):
        return None
    try:
        resp = requests.get(raw, timeout=30, headers={"User-Agent": "argus-rules"})
        resp.raise_for_status()
        text = resp.text
        if len(text) > _MAX_RULE_CHARS:
            text = text[:_MAX_RULE_CHARS] + "\n# … (생략 — 전체는 출처 링크 참조)"
        return text
    except requests.exceptions.RequestException as e:
        logger.debug(f"룰 원문 수신 실패({raw}): {e}")
        return None


class RuleManager:
    def __init__(self):
        logger.debug("RuleManager 초기화 (인덱스 조회 전용)")


    @staticmethod
    def lookup(cve_id: str) -> List[Dict]:
        return _index().get(cve_id.upper(), [])


    def search_public_only(self, cve_id: str) -> Tuple[Dict, bool]:
        entries = self.lookup(cve_id)
        rules: Dict = {"sigma": None, "network": [], "yara": None,
                       "nuclei": None, "splunk": None}
        if not entries:
            return rules, True

        missed = 0
        for entry in entries:
            engine = entry.get("engine", "")
            # 라이선스 표기는 색인 시점이 아니라 지금 표로 다시 정한다(옛 색인의 표기도 바로잡힌다).
            packed = rule_license.apply({
                "source": entry.get("source", ""),
                "engine": engine,
                "url": entry.get("url", ""),
                "author": entry.get("author", ""),
                "license_url": entry.get("license_url", ""),
            })
            if packed.get("link_only"):
                # 본문을 싣지 않는 룰(점검 템플릿 · 라이선스를 확인하지 못한 YARA) — 원문을 받지 않는다.
                if not rules.get(engine):
                    rules[engine] = packed
            elif engine in rule_license.NETWORK_ENGINES:
                if len(rules["network"]) >= 3:
                    continue
                code = _fetch_text(entry)
                if code:
                    rules["network"].append({**packed, "code": code})
                else:
                    missed += 1
            elif engine in ("sigma", "yara", "splunk"):
                # 본문을 실을 수 있는 룰이 링크만 둔 룰보다 앞선다.
                if rules.get(engine) and not rules[engine].get("link_only"):
                    continue
                code = _fetch_text(entry)
                if code:
                    rules[engine] = {**packed, "code": code,
                                     "author": packed["author"] or author_of(code)}
                else:
                    missed += 1

        if missed:
            logger.warning(f"  {cve_id}: 색인에 있는 룰 {missed}건의 원문을 받지 못했다 "
                           f"— '룰 없음'으로 기록하지 않는다")
            return rules, False

        found = [k for k in ("sigma", "yara", "nuclei", "splunk") if rules.get(k)]
        if rules["network"]:
            found.append(f"network({len(rules['network'])})")
        if found:
            logger.info(f"  ✅ 공개 룰: {cve_id} — {', '.join(found)}")
        return rules, True
