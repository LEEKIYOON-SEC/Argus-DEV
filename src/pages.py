import json
import os
import urllib.request
from typing import Optional

_UA = {"User-Agent": "argus"}
_TIMEOUT = 60

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "data"
)


def base_url() -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None
    owner, name = repo.split("/", 1)
    return f"https://{owner.lower()}.github.io/{name}/"


def dashboard_url() -> Optional[str]:
    return base_url()


def cve_url(cve_id: str) -> Optional[str]:
    base = base_url()
    return f"{base}cve.html?cve={cve_id}" if base else None


def data_url(filename: str = "") -> Optional[str]:
    base = base_url()
    if not base:
        return None
    return f"{base}data/{filename}" if filename else f"{base}data"


def fetch_published(filename: str, timeout: int = _TIMEOUT) -> Optional[bytes]:
    url = data_url(filename)
    if not url:
        return None
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_published_json(filename: str, timeout: int = _TIMEOUT):
    payload = fetch_published(filename, timeout=timeout)
    return None if payload is None else json.loads(payload.decode("utf-8"))


def write_json(path: str, payload) -> None:
    # 화면이 받는 파일(cves.json · cve-products.json · stats.json)이라 들여쓰기 없이 쓴다 — 실측 2026-11-24 cves.json
    # 63.9MB 중 줄바꿈 · 들여쓰기가 차지하던 몫을 받지 않는다. 사람이 읽을 파일(저장소의 수명주기 데이터)은 따로 쓴다.
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)
