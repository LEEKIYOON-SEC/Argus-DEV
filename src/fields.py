import datetime
import re

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
CWE_RE = re.compile(r'CWE-\d{1,4}\b')

_JUNK = ("", "unknown", "n/a", "-", "n/a (단일 버전)", "정보 없음")


def meaningful(v) -> str:
    s = str(v or "").strip()
    return "" if s.lower() in _JUNK else s


def record_time(value) -> str:
    """CVE 레코드의 시각(cveMetadata 의 dateUpdated 등) → UTC 'YYYY-MM-DDTHH:MM:SSZ'.

    시간대가 없으면 UTC 다(CVE JSON 5 규약). 읽지 못하면 '' — 출처가 준 값만 쓰고 지어내지 않는다.
    """
    s = str(value or "").strip()
    if not s:
        return ""
    try:
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
