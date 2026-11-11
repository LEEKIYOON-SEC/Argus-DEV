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


def cache_get(name: str, ttl_hours: int = _CACHE_TTL_HOURS) -> Optional[bytes]:
    path = os.path.join(_CACHE_DIR, name)
    try:
        if os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            if age < ttl_hours * 3600:
                with open(path, "rb") as f:
                    return f.read()
    except OSError as e:
        logger.debug(f"캐시 읽기 실패 ({name}): {e}")
    return None


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
_poc_loaded = False
_poc_ok = False
_POC_BLOCK = re.compile(rf"^### ({CVE_RE.pattern})", re.M)
_POC_LINK = re.compile(r"https://github\.com/[^\s\)\]]+")


def load_poc_index() -> Dict[str, List[str]]:
    global _poc_loaded, _poc_ok
    with _lock:
        if _poc_loaded:
            return _poc_index
        _poc_loaded = True

        raw = cache_get("poc-in-github.md")
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
            parts = _POC_BLOCK.split(raw.decode("utf-8", errors="ignore"))
            for i in range(1, len(parts) - 1, 2):
                urls = _POC_LINK.findall(parts[i + 1])
                if urls:
                    _poc_index[parts[i].upper()] = urls[:3]
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
