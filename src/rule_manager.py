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
# 색인을 만든 시각 — 매시 재확인이 같은 색인으로는 CVE 마다 한 번만 보게 한다(rule_refresh). 옛 색인에는 없다.
_META: Dict = {"generated_at": ""}

_LOCAL = os.path.join(pages.DATA_DIR, "detection-rules.json")

_MAX_RULE_CHARS = 6000
_SID = re.compile(r"\bsid\s*:\s*(\d+)")


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


def built_at() -> str:
    _index()
    return _META["generated_at"]


def indexed_ids() -> List[str]:
    return list(_index())


def _keep_meta(payload: Dict) -> None:
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


_LINES = re.compile(r"#L(\d+)(?:-L(\d+))?$")
_CUT_MARK = "\n# … (생략 — 전체는 출처 링크 참조)"


def _overrun(rule: Dict) -> bool:
    """스냅샷 본문이 링크의 줄 범위보다 긴가 — 범위로 자르기 전에 파일 앞부분을 통째로 실은 옛 스냅샷이다."""
    m = _LINES.search(rule.get("url") or "")
    code = rule.get("code")
    if not m or not isinstance(code, str):
        return False
    span = int(m.group(2) or m.group(1)) - int(m.group(1)) + 1
    body = code[:-len(_CUT_MARK)] if code.endswith(_CUT_MARK) else code
    return span > 0 and len(body.splitlines()) > span


def _cut(text: str, url: str) -> str:
    """URL 끝의 #L2-L31 범위만 남긴다 — 여러 룰이 든 파일에서 이 CVE 의 룰만 싣기 위해서다.

    파일 앞 6000자를 그대로 실으면 범위가 뒤쪽인 룰은 다른 룰의 본문이 실린다(실측 YARA 66건 중 9건).
    범위가 없거나 파일보다 뒤면 자르지 않는다.
    """
    m = _LINES.search(url)
    if not m:
        return text
    first = int(m.group(1))
    last = int(m.group(2) or first)
    lines = text.splitlines()
    if first < 1 or last < first or first > len(lines):
        return text
    return "\n".join(lines[first - 1:last])


def _fetch_text(entry: Dict) -> Optional[str]:
    if entry.get("code"):
        return entry["code"]
    url = entry.get("url") or ""
    raw = (_LINES.sub("", url).replace("https://github.com/", "https://raw.githubusercontent.com/")
           .replace("/blob/", "/"))
    if not raw.startswith("http"):
        return None
    try:
        resp = requests.get(raw, timeout=30, headers={"User-Agent": "argus-rules"})
        resp.raise_for_status()
        text = _cut(resp.text, url)
        if len(text) > _MAX_RULE_CHARS:
            text = text[:_MAX_RULE_CHARS] + _CUT_MARK
        return text
    except requests.exceptions.RequestException as e:
        logger.debug(f"룰 원문 수신 실패({raw}): {e}")
        return None


def _pack(entry: Dict) -> Dict:
    # 라이선스 표기는 색인 시점이 아니라 지금 표로 다시 정한다(옛 색인의 표기도 바로잡힌다).
    return rule_license.apply({
        "source": entry.get("source", ""),
        "engine": entry.get("engine", ""),
        "url": entry.get("url", ""),
        "author": entry.get("author", ""),
        "license_url": entry.get("license_url", ""),
    })


Pick = Tuple[Dict, Dict]  # (색인 항목, 라이선스 표기를 바로잡은 사본)


def _choose(entries: List[Dict]) -> Tuple[List[Pick], Dict[str, Pick]]:
    """스냅샷에 실을 색인 항목 — (네트워크 룰, 엔진마다 하나씩 싣는 룰).

    네트워크 룰은 색인에 있는 것을 다 싣고 엔진별로 묶는다(색인이 엔진마다 3건까지 담아 CVE 당 최대 12건).
    CVE 당 3건으로 자르면 같은 CVE 의 다른 룰이 화면에 나오지 않았다(INVARIANTS §6).
    sigma · yara · splunk 는 본문을 실을 수 있는 룰이 링크만 둔 룰보다 앞선다.
    """
    queues: Dict[str, List[Pick]] = {}
    single: Dict[str, Pick] = {}
    for entry in entries:
        engine = entry.get("engine", "")
        packed = _pack(entry)
        if packed.get("link_only"):
            single.setdefault(engine, (entry, packed))
        elif engine in rule_license.NETWORK_ENGINES:
            queues.setdefault(engine, []).append((entry, packed))
        elif engine in ("sigma", "yara", "splunk"):
            if engine not in single or single[engine][1].get("link_only"):
                single[engine] = (entry, packed)
    return [pick for queue in queues.values() for pick in queue], single


def rule_key(rule: Dict) -> Tuple[str, str]:
    """같은 룰인지 견주는 열쇠 — 네트워크 룰은 출처와 SID(본문의 sid), 나머지는 링크.
    색인 항목과 스냅샷의 룰에 똑같이 쓴다(스냅샷은 색인 항목의 source · url · 본문을 그대로 싣는다)."""
    engine = rule.get("engine") or ""
    if engine in rule_license.NETWORK_ENGINES:
        code = (rule.get("code") or "").strip()
        m = _SID.search(code)
        return engine, f"{rule.get('source') or ''}:sid{m.group(1)}" if m else code
    return engine, rule.get("url") or ""


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
        network, single = _choose(entries)
        for entry, packed in network:
            code = _fetch_text(entry)
            if code:
                rules["network"].append({**packed, "code": code})
            else:
                missed += 1
        for engine, (entry, packed) in single.items():
            if packed.get("link_only"):
                # 본문을 싣지 않는 룰(점검 템플릿 · 라이선스를 확인하지 못한 YARA) — 원문을 받지 않는다.
                rules[engine] = packed
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


def missing(cve_id: str, snapshot) -> bool:
    """지금 색인으로 다시 찾으면 스냅샷이 달라지는가 — 원문은 받지 않고 search_public_only 가 고를 룰만 견준다.

    스냅샷에 없는 룰이 있거나, 본문이 링크의 줄 범위보다 길면(다른 룰까지 실린 옛 스냅샷) 다시 본다.
    """
    network, single = _choose(RuleManager.lookup(cve_id))
    want = {rule_key(entry) for entry, _ in network + list(single.values())}
    snap = snapshot if isinstance(snapshot, dict) else {}
    have = {rule_key(r) for r in (snap.get("network") or []) if isinstance(r, dict)}
    singles = [r for k, r in snap.items() if k != "network" and isinstance(r, dict)]
    have.update(rule_key(r) for r in singles)
    return bool(want - have) or any(_overrun(r) for r in singles)
