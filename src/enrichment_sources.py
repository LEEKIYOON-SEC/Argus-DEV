import collections
import csv
import functools
import io
import json
import os
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

import requests

from fields import CVE_RE
from logger import logger
from rate_limiter import rate_limit_manager

_CACHE_DIR = os.environ.get(
    "ARGUS_CACHE_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache", "rulesets")
)
_CACHE_TTL_HOURS = 24

EXPLOITDB_RAW_BASE = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
_METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
_NUCLEI_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
_POC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_VULNCHECK_BACKUP_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"

_lock = threading.Lock()

_MAX_LIMIT_WAIT = 30


def memo_ok(fn):
    box: Dict[str, object] = {}
    lock = threading.Lock()

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with lock:
            if "v" in box:
                return box["v"]
            out = fn(*args, **kwargs)
            if out is not None:
                box["v"] = out
            return out

    return wrapper


def cache_get(name: str, ttl_hours: int = _CACHE_TTL_HOURS,
              since: Optional[float] = None) -> Optional[bytes]:
    """캐시 파일 — ttl_hours 안에 받은 것, since 를 주면 그 시각 이후에 받은 것만."""
    path = os.path.join(_CACHE_DIR, name)
    try:
        if os.path.exists(path):
            mtime = os.path.getmtime(path)
            fresh = mtime >= since if since is not None else time.time() - mtime < ttl_hours * 3600
            if fresh:
                with open(path, "rb") as f:
                    return f.read()
    except OSError as e:
        logger.debug(f"캐시 읽기 실패 ({name}): {e}")
    return None


def this_hour_start(now: Optional[float] = None) -> float:
    """지금 UTC 시(時)의 시작 시각 — Actions 캐시 키(date -u +%Y-%m-%d-%H)와 같은 단위."""
    t = time.time() if now is None else now
    return t - (t % 3600)


def cache_put(name: str, content: bytes) -> None:
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        path = os.path.join(_CACHE_DIR, name)
        with open(path, "wb") as f:
            f.write(content)
    except OSError as e:
        logger.debug(f"캐시 쓰기 실패 ({name}): {e}")


def cache_drop(name: str) -> None:
    """읽을 수 없는 캐시를 지운다 — 받은 직후에 저장하므로, 깨진 응답(오류 페이지 등)이 캐시 수명 동안 남지 않게."""
    try:
        os.remove(os.path.join(_CACHE_DIR, name))
    except OSError:
        pass


_exploitdb_index: Dict[str, Tuple[str, str]] = {}
_exploitdb_loaded = False
_exploitdb_ok = False


def load_exploitdb_index() -> Dict[str, Tuple[str, str]]:
    global _exploitdb_loaded, _exploitdb_ok
    with _lock:
        if _exploitdb_loaded:
            return _exploitdb_index
        _exploitdb_loaded = True

        raw = cache_get("exploitdb-files.csv")
        if raw is None:
            logger.info("📥 Exploit-DB CSV 인덱스 다운로드 중...")
            try:
                if not rate_limit_manager.check_and_wait("ruleset_download", max_wait=_MAX_LIMIT_WAIT):
                    raise RuntimeError("ruleset_download 한도 대기가 너무 길어 이번 회차는 건너뛴다")
                response = requests.get(EXPLOITDB_RAW_BASE + "files_exploits.csv", timeout=60)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("exploitdb-files.csv", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ Exploit-DB CSV 다운로드 실패: {e}")
                return _exploitdb_index
        else:
            logger.info("📥 Exploit-DB CSV 인덱스 캐시 로드")

        try:
            reader = csv.DictReader(io.StringIO(raw.decode('utf-8', errors='ignore')))
            for row in reader:
                codes = row.get("codes", "") or ""
                file_path = row.get("file", "") or ""
                edb_id = row.get("id", "") or ""
                if not file_path:
                    continue
                for cve in CVE_RE.findall(codes):
                    _exploitdb_index.setdefault(cve.upper(), (file_path, edb_id))
            _exploitdb_ok = bool(_exploitdb_index)
            logger.info(f"  ✅ Exploit-DB 인덱스 로드 완료 ({len(_exploitdb_index)}개 CVE 매핑)")
        except Exception as e:
            logger.warning(f"  ⚠️ Exploit-DB CSV 파싱 실패: {e}")
        if not _exploitdb_ok:
            cache_drop("exploitdb-files.csv")

    return _exploitdb_index


def exploitdb_ok() -> bool:
    load_exploitdb_index()
    return _exploitdb_ok


def exploitdb_entry(cve_id: str) -> Optional[Tuple[str, str]]:
    load_exploitdb_index()
    return _exploitdb_index.get(cve_id.upper())


_msf_index: Dict[str, List[Dict]] = {}
_msf_loaded = False
_msf_ok = False

_MSF_RANK_NAMES = {
    0: "manual", 100: "low", 200: "average", 300: "normal",
    400: "good", 500: "great", 600: "excellent",
}


def load_metasploit_index() -> Dict[str, List[Dict]]:
    global _msf_loaded, _msf_ok
    with _lock:
        if _msf_loaded:
            return _msf_index
        _msf_loaded = True

        raw = cache_get("metasploit-modules.json")
        if raw is None:
            logger.info("📥 Metasploit 메타데이터 다운로드 중...")
            try:
                if not rate_limit_manager.check_and_wait("ruleset_download", max_wait=_MAX_LIMIT_WAIT):
                    raise RuntimeError("ruleset_download 한도 대기가 너무 길어 이번 회차는 건너뛴다")
                response = requests.get(_METASPLOIT_URL, timeout=60)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("metasploit-modules.json", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ Metasploit 메타데이터 다운로드 실패: {e}")
                return _msf_index
        else:
            logger.info("📥 Metasploit 메타데이터 캐시 로드")

        try:
            data = json.loads(raw.decode('utf-8', errors='ignore'))
            for _path, meta in data.items():
                refs = meta.get("references", []) or []
                cves = set()
                for ref in refs:
                    if isinstance(ref, str):
                        for m in CVE_RE.findall(ref.replace(",", "-")):
                            cves.add(m.upper())
                if not cves:
                    continue
                rank = meta.get("rank", 0)
                entry = {
                    "fullname": meta.get("fullname", meta.get("name", "")),
                    "rank": rank,
                    "rank_name": _MSF_RANK_NAMES.get(rank, str(rank)),
                    "type": meta.get("type", ""),
                }
                for cve in cves:
                    _msf_index.setdefault(cve, []).append(entry)
            _msf_ok = bool(_msf_index)
            logger.info(f"  ✅ Metasploit 인덱스 로드 완료 ({len(_msf_index)}개 CVE 매핑)")
        except Exception as e:
            logger.warning(f"  ⚠️ Metasploit 메타데이터 파싱 실패: {e}")
        if not _msf_ok:
            cache_drop("metasploit-modules.json")

    return _msf_index


def metasploit_ok() -> bool:
    load_metasploit_index()
    return _msf_ok


def metasploit_modules(cve_id: str) -> List[Dict]:
    load_metasploit_index()
    mods = _msf_index.get(cve_id.upper(), [])
    return sorted(mods, key=lambda m: m.get("rank", 0), reverse=True)


_nuclei_index: Dict[str, Dict] = {}
_nuclei_loaded = False
_nuclei_ok = False


def load_nuclei_index() -> Dict[str, Dict]:
    global _nuclei_loaded, _nuclei_ok
    with _lock:
        if _nuclei_loaded:
            return _nuclei_index
        _nuclei_loaded = True

        raw = cache_get("nuclei-cves.json")
        if raw is None:
            logger.info("📥 nuclei-templates 인덱스 다운로드 중...")
            try:
                if not rate_limit_manager.check_and_wait("ruleset_download", max_wait=_MAX_LIMIT_WAIT):
                    raise RuntimeError("ruleset_download 한도 대기가 너무 길어 이번 회차는 건너뛴다")
                response = requests.get(_NUCLEI_URL, timeout=60)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("nuclei-cves.json", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ nuclei-templates 다운로드 실패: {e}")
                return _nuclei_index
        else:
            logger.info("📥 nuclei-templates 인덱스 캐시 로드")

        try:
            for line in raw.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                cve_id = str(obj.get("ID") or "").upper()
                if not cve_id.startswith("CVE-"):
                    continue
                info = obj.get("Info") or {}
                _nuclei_index[cve_id] = {
                    "name": info.get("Name", ""),
                    "severity": info.get("Severity", ""),
                    "path": obj.get("file_path", ""),
                }
            _nuclei_ok = bool(_nuclei_index)
            logger.info(f"  ✅ nuclei-templates 인덱스 로드 완료 ({len(_nuclei_index)}개 CVE 매핑)")
        except Exception as e:
            logger.warning(f"  ⚠️ nuclei-templates 파싱 실패: {e}")
        if not _nuclei_ok:
            cache_drop("nuclei-cves.json")

    return _nuclei_index


def nuclei_ok() -> bool:
    load_nuclei_index()
    return _nuclei_ok


def nuclei_template(cve_id: str) -> Optional[Dict]:
    load_nuclei_index()
    return _nuclei_index.get(cve_id.upper())


def nuclei_template_url(path: str) -> str:
    return f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}"


_poc_index: Dict[str, List[str]] = {}
# README 제목 옆 날짜 — PoC-in-GitHub 가 적어 둔 CVE 공개일. 아직 못 받았으면(공개 직후 · 공개 전) 없다.
_poc_dates: Dict[str, str] = {}
_poc_loaded = False
_poc_ok = False
# 블록 경계는 모든 '### ' 제목이다. CVE 형식인 제목만 색인한다 — 'CVE-2026-30' 처럼 번호가 틀린 제목을 경계로
# 보지 않으면 그 아래 링크가 바로 앞 CVE 에 붙었다(실측 11건, 예: CVE-2024-0986 에 PAN-OS 익스플로잇 링크).
_POC_BOUNDARY = re.compile(r"^### ", re.M)
_POC_HEAD = re.compile(rf"### ({CVE_RE.pattern})(?: \((\d{{4}}-\d{{2}}-\d{{2}})\))?")
_POC_LINK = re.compile(r"https://github\.com/[^\s\)\]]+")
# 저장소 줄 '- [owner/repo](https://github.com/owner/repo)' — 저장소 수와 별칭은 이 줄만 센다(설명 속 링크는 빼고).
_POC_REPO = re.compile(r"^- \[[^\]]*\]\(https://github\.com/([^/\s\)]+)/([^/\s\)]+)\)", re.M)
_poc_counts: Dict[str, int] = {}
_poc_nicks: Dict[str, List[Tuple[str, int]]] = {}     # CVE → [(key, 그 이름을 쓴 서로 다른 주인 수)]
# 별칭 표기는 CVE 마다 고르지 않고 색인 전체에서 고른다 — 같은 이름이 CVE 마다 WP2Shell · Wp2Shell 로 갈리지 않게.
_nick_spell: Dict[str, "collections.Counter"] = collections.defaultdict(collections.Counter)

# 별칭 — 'PHP2Shell · Java4Shell' 꼴(화제가 된 취약점에 붙는 이름). CVE 레코드에는 이런 이름이 없고 PoC 저장소 ·
# 탐지 템플릿 이름에만 나온다(실측 2026-11-19). 앞부분은 글자로 시작하고 글자로 끝나야 한다 — Metasploit 페이로드
# 이름(aarch64shell · x64shell)이 4shell 로 읽히지 않게. 'Log4ShellScanner' 처럼 대문자로 이어 붙인 이름은 잡고,
# 'log4shells' 처럼 소문자가 이어지면 다른 낱말로 본다.
_NICK = re.compile(r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9]{0,18}[A-Za-z])[-_ ]?([24])[-_ ]?shell(?!(?-i:[a-z0-9]))", re.I)
# 서로 다른 저장소 주인이 이만큼 같은 이름을 써야 별칭으로 본다 — 한두 명이 엉뚱한 CVE 에 붙인 이름을 거른다
# (예: php2shell 이 CVE-2025-55182 · CVE-2024-4577 에 한 명씩). 실측에서 3명 이상은 13건이었고 철회 1건 말고 모두 T0/T1.
NICKNAME_MIN_OWNERS = 3
NICKNAME_MAX = 3


def nickname_parts(text: str) -> List[Tuple[str, str]]:
    """글에서 별칭 후보 — (key, 쓴 대로의 앞부분과 숫자). key 는 소문자('php2shell'), 둘째는 'PHP2' 처럼."""
    return [(f"{m.group(1).lower()}{m.group(2)}shell", f"{m.group(1)}{m.group(2)}") for m in _NICK.finditer(text or "")]


def _nick_display(spellings: "collections.Counter") -> str:
    """가장 많이 쓴 표기 — 대문자가 섞인 표기(PHP2 · Java4)를 먼저 고르고, 없으면 첫 글자만 대문자로."""
    cased = [(n, s) for s, n in spellings.items() if any(ch.isupper() for ch in s)]
    if cased:
        return f"{max(cased)[1]}Shell"
    best = max((n, s) for s, n in spellings.items())[1]
    return f"{best[:1].upper()}{best[1:]}Shell"


def _nicknames_of(repos: List[Tuple[str, str]]) -> List[Tuple[str, int]]:
    """저장소(주인, 이름) 목록에서 별칭 — (key, 그 이름을 쓴 서로 다른 주인 수), 많이 쓴 순.
    표기는 색인 전체에 모아(_nick_spell) nickname_display 가 고른다."""
    owners: Dict[str, set] = collections.defaultdict(set)
    for owner, repo in repos:
        for key, shown in nickname_parts(repo):
            owners[key].add(owner.lower())
            _nick_spell[key][shown] += 1
    found = sorted(((len(o), key) for key, o in owners.items() if len(o) >= NICKNAME_MIN_OWNERS),
                   key=lambda x: (-x[0], x[1]))
    return [(key, n) for n, key in found[:NICKNAME_MAX]]


def nickname_display(key: str) -> str:
    """별칭 key('wp2shell')의 표기 — PoC 저장소 이름에서 가장 많이 쓴 것. 색인에 없으면 빈 글."""
    load_poc_index()
    spellings = _nick_spell.get(key)
    return _nick_display(spellings) if spellings else ""


def load_poc_index() -> Dict[str, List[str]]:
    global _poc_loaded, _poc_ok
    with _lock:
        if _poc_loaded:
            return _poc_index
        _poc_loaded = True

        # PoC 는 레코드를 판정하는 그 순간의 색인으로 확인한다 — 24시간 묵을 수 있는 색인이면 공개 전에 이미
        # 올라온 PoC 도 놓칠 수 있다(CVE-2026-114938: PoC 가 공개 6시간 전에 있었는데 판정 때 색인에 없었다).
        # 이번 시(時)에 받은 것만 쓰고, 시간 단위 Actions 캐시 키와 맞물려 레인마다 한 시간에 한 번 받는다.
        # 날짜 단위 키에 이 규칙을 쓰면 5분 회차마다 7.5MB 를 다시 받는다.
        raw = cache_get("poc-in-github.md", since=this_hour_start())
        if raw is None:
            logger.info("📥 PoC-in-GitHub 인덱스 다운로드 중...")
            try:
                if not rate_limit_manager.check_and_wait("ruleset_download", max_wait=_MAX_LIMIT_WAIT):
                    raise RuntimeError("ruleset_download 한도 대기가 너무 길어 이번 회차는 건너뛴다")
                response = requests.get(_POC_URL, timeout=120)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("poc-in-github.md", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ PoC-in-GitHub 다운로드 실패: {e}")
                return _poc_index
        else:
            logger.info("📥 PoC-in-GitHub 인덱스 캐시 로드")

        try:
            text = raw.decode("utf-8", errors="ignore")
            starts = [b.start() for b in _POC_BOUNDARY.finditer(text)] + [len(text)]
            for start, end in zip(starts, starts[1:]):
                m = _POC_HEAD.match(text, start)
                if not m:
                    continue
                urls = _POC_LINK.findall(text, m.end(), end)
                if urls:
                    cve_id = m.group(1).upper()
                    _poc_index[cve_id] = urls[:3]
                    if m.group(2):
                        _poc_dates[cve_id] = m.group(2)
                    repos = _POC_REPO.findall(text, m.end(), end)
                    if repos:
                        _poc_counts[cve_id] = len({(o.lower(), r.lower()) for o, r in repos})
                        nicks = _nicknames_of(repos)
                        if nicks:
                            _poc_nicks[cve_id] = nicks
            _poc_ok = bool(_poc_index)
            logger.info(f"  ✅ PoC 인덱스 로드 완료 ({len(_poc_index)}개 CVE 매핑)")
        except Exception as e:
            logger.warning(f"  ⚠️ PoC-in-GitHub 파싱 실패: {e}")
        if not _poc_ok:
            cache_drop("poc-in-github.md")

    return _poc_index


def poc_ok() -> bool:
    load_poc_index()
    return _poc_ok


def poc_urls(cve_id: str) -> List[str]:
    load_poc_index()
    return _poc_index.get(cve_id.upper(), [])


def poc_dates() -> Dict[str, str]:
    """PoC 색인에 있는 CVE 의 공개일(README 표기) — 날짜가 없는 CVE 는 빠져 있다."""
    load_poc_index()
    return _poc_dates


def poc_count(cve_id: str) -> int:
    """PoC 색인에 올라온 이 CVE 의 저장소 수 — 화제 정도를 보여 주는 값이다. 판정에는 쓰지 않는다."""
    load_poc_index()
    return _poc_counts.get(str(cve_id).upper(), 0)


def poc_nicknames(cve_id: str) -> List[Tuple[str, int]]:
    """PoC 저장소 이름에서 모은 별칭 — (표기, 그 이름을 쓴 서로 다른 주인 수), 많이 쓴 순."""
    load_poc_index()
    return [(_nick_display(_nick_spell[key]), n) for key, n in _poc_nicks.get(str(cve_id).upper(), [])]


def tool_nicknames(cve_id: str, nuclei: bool = True, msf: bool = True) -> List[Tuple[str, str]]:
    """nuclei 템플릿 이름 · Metasploit 모듈 경로에 적힌 별칭 — (표기, 출처). 사람이 붙인 이름이라 한 곳이면 인정한다.

    nuclei 는 'WordPress Core < 7.0.3 - Preauth Reflected XSS (XSS2Shell)' 처럼 표기를 그대로 쓴다.
    Metasploit 경로는 소문자라('…/react2shell_rce') 첫 글자만 대문자로 적는다.
    """
    out: List[Tuple[str, str]] = []
    if nuclei:
        tpl = nuclei_template(cve_id)
        for _key, shown in nickname_parts((tpl or {}).get("name", "")):
            out.append((f"{shown}Shell", "nuclei"))
    if msf:
        for mod in metasploit_modules(cve_id):
            for _key, shown in nickname_parts(str(mod.get("fullname") or "").replace("/", " ")):
                out.append((f"{shown[:1].upper()}{shown[1:]}Shell", "metasploit"))
    return out


@memo_ok
def load_cisa_kev(ttl_hours: int = 1) -> Optional[Dict[str, Dict]]:
    raw = cache_get("cisa-kev.json", ttl_hours=ttl_hours)
    if raw is None:
        try:
            if not rate_limit_manager.check_and_wait("kev", max_wait=_MAX_LIMIT_WAIT):
                raise RuntimeError("kev 한도 대기가 너무 길어 이번 회차는 건너뛴다")
            response = requests.get(_CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            rate_limit_manager.record_call("kev")
            raw = response.content
            cache_put("cisa-kev.json", raw)
        except Exception as e:
            logger.error(f"CISA KEV 수신 실패: {e}")
            return None
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except ValueError as e:
        logger.error(f"CISA KEV 파싱 실패: {e}")
        cache_drop("cisa-kev.json")
        return None
    out = {}
    for item in data.get("vulnerabilities", []) or []:
        cve_id = item.get("cveID")
        if cve_id:
            out[cve_id.upper()] = item
    logger.info(f"📥 CISA KEV {len(out)}건")
    return out


def _vulncheck_download_url(api_key: str) -> Optional[str]:
    try:
        if not rate_limit_manager.check_and_wait("vulncheck", max_wait=_MAX_LIMIT_WAIT):
            logger.warning("VulnCheck 한도 대기가 너무 길어 이번 회차는 건너뛴다")
            return None
        resp = requests.get(
            _VULNCHECK_BACKUP_URL,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=60,
        )
        rate_limit_manager.record_call("vulncheck")
        if resp.status_code == 401:
            logger.error(
                "VulnCheck KEV 401 — 토큰이 거부됐습니다. 확인할 것: "
                "① VULNCHECK_API_KEY 값이 맞는지(앞뒤 공백·따옴표 포함) "
                "② vulncheck.com 계정에서 토큰이 활성 상태인지. "
                "이 신호 없이도 파이프라인은 정상 동작합니다(CISA KEV로 대체)."
            )
            return None
        resp.raise_for_status()
        entries = (resp.json() or {}).get("data") or []
        url = entries[0].get("url") if entries else None
        if not url:
            logger.warning("VulnCheck KEV: 백업 목록이 비어 있음")
        return url
    except requests.exceptions.RequestException as e:
        logger.warning(f"VulnCheck KEV 백업 URL 조회 실패: {e}")
        return None


def _vulncheck_records(payload: bytes) -> list:
    import io
    import zipfile

    if payload[:2] == b"PK":
        out = []
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        doc = json.loads(zf.read(name).decode("utf-8", errors="ignore"))
                    except ValueError:
                        continue
                    if isinstance(doc, list):
                        out.extend(doc)
                    elif isinstance(doc, dict):
                        out.extend(doc.get("data") or [])
        except zipfile.BadZipFile as e:
            logger.warning(f"VulnCheck KEV 아카이브 해제 실패: {e}")
        return out
    try:
        doc = json.loads(payload.decode("utf-8", errors="ignore"))
    except ValueError as e:
        logger.warning(f"VulnCheck KEV 파싱 실패: {e}")
        return []
    return doc if isinstance(doc, list) else (doc.get("data") or [])


@memo_ok
def load_vulncheck_kev(ttl_hours: int = 6) -> Optional[Dict[str, Dict]]:
    api_key = (os.environ.get("VULNCHECK_API_KEY") or "").strip()
    if not api_key:
        logger.debug("VULNCHECK_API_KEY 미설정 → VulnCheck KEV 건너뜀")
        return None

    raw = cache_get("vulncheck-kev.bin", ttl_hours=ttl_hours)
    if raw is None:
        url = _vulncheck_download_url(api_key)
        if not url:
            return None
        try:
            resp = requests.get(url, timeout=120)
            resp.raise_for_status()
            raw = resp.content
            cache_put("vulncheck-kev.bin", raw)
            logger.info(f"📥 VulnCheck KEV 스냅샷 수신 ({len(raw) / 1024 / 1024:.1f}MB)")
        except requests.exceptions.RequestException as e:
            logger.warning(f"VulnCheck KEV 스냅샷 수신 실패: {e}")
            return None

    out: Dict[str, Dict] = {}
    for item in _vulncheck_records(raw):
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID") or item.get("cve_id")
        if not cve_id:
            arr = item.get("cve") or []
            cve_id = arr[0] if isinstance(arr, list) and arr else None
        if cve_id:
            out[str(cve_id).upper()] = item
    if not out:
        logger.warning("VulnCheck KEV: 레코드를 하나도 읽지 못함 → 이번 회차 생략")
        cache_drop("vulncheck-kev.bin")
        return None
    logger.info(f"📥 VulnCheck KEV {len(out)}건 (This product uses VulnCheck KEV)")
    return out


_EPSS_CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


@memo_ok
def load_epss_full(ttl_hours: int = 6) -> Optional[Dict[str, Tuple[float, float]]]:
    import gzip

    raw = cache_get("epss-full.csv.gz", ttl_hours=ttl_hours)
    if raw is None:
        try:
            if not rate_limit_manager.check_and_wait("epss", max_wait=_MAX_LIMIT_WAIT):
                raise RuntimeError("epss 한도 대기가 너무 길어 이번 회차는 건너뛴다")
            response = requests.get(_EPSS_CURRENT_URL, timeout=120, allow_redirects=True)
            response.raise_for_status()
            rate_limit_manager.record_call("epss")
            raw = response.content
            cache_put("epss-full.csv.gz", raw)
            logger.info(f"📥 EPSS 전량 덤프 수신 ({len(raw) / 1024 / 1024:.1f}MB)")
        except Exception as e:
            logger.warning(f"EPSS 전량 덤프 수신 실패: {e}")
            return None
    else:
        logger.info("📥 EPSS 전량 덤프 캐시 로드")

    try:
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"EPSS 덤프 압축 해제 실패: {e}")
        cache_drop("epss-full.csv.gz")
        return None

    out: Dict[str, Tuple[float, float]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            out[parts[0].upper()] = (float(parts[1]), float(parts[2]))
        except ValueError:
            continue
    logger.info(f"  ✅ EPSS {len(out):,}건 (점수 + percentile)")
    return out


def load_epss_above(min_percentile: float) -> Optional[Dict[str, Tuple[float, float]]]:
    full = load_epss_full()
    if full is None:
        return None
    out = {cve: v for cve, v in full.items() if v[1] >= min_percentile}
    logger.info(f"  EPSS p{min_percentile:.0%} 이상 {len(out):,}건만 유지")
    return out
