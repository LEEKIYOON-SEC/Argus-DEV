"""번역 대상 고르기 · 제목 규칙 · 번역 결과 판정 — main.translate_tracked 가 쓴다.

모델을 부르지 않는 함수만 둔다. 그래서 테스트가 그대로 부른다.

· 보이는 제목에 한글이 없으면(영어 제목 · CVE 번호뿐인 제목) 번역 대상이다.
· 번역이 실패하면(서버 오류 · 한도 · 시간 초과) 아무 표시도 남기지 않는다 — 다음 회차가 다시 보낸다.
  모델이 답했는데도 쓸 수 없을 때만 '시도함'(ko_tried · ko_rule)을 적는다.
· '제품 이름 + 취약점'뿐인 제목(유형이 없는 제목)은 남는 한도로 조금씩 다시 만든다.
"""
import json
import os
import re
from typing import Dict, Optional, Tuple

from fields import meaningful

# 제목 규칙 판. 규칙을 바꾸면 올린다 — 그 전 판으로 답을 받은 행(ko_rule < 이 값)을 한 번씩 다시 본다.
TITLE_RULE = 1

_HANGUL = re.compile(r"[가-힣]")
_LATIN = re.compile(r"[A-Za-z]")
_CVE_ONLY = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def has_hangul(text) -> bool:
    return bool(_HANGUL.search(str(text or "")))


def looks_english(text) -> bool:
    t = str(text or "").strip()
    if not t or t in ("N/A", "-") or has_hangul(t):
        return False
    return len(_LATIN.findall(t)) >= 8


def is_cve_id_only(text) -> bool:
    return bool(_CVE_ONLY.match(str(text or "").strip()))


def shown_title(state: Dict) -> str:
    return str(state.get("title_ko") or state.get("title") or "").strip()


def shown_desc(state: Dict) -> str:
    return str(state.get("desc_ko") or state.get("description") or "").strip()


def title_key(state: Dict) -> str:
    """'시도함' 표시가 가리키는 제목 — 출처 제목이 바뀌면 표시가 풀린다."""
    return str(state.get("title") or shown_title(state))


def rule_of(state: Dict) -> int:
    try:
        return int(state.get("ko_rule") or 0)
    except (TypeError, ValueError):
        return 0


def needs_title(state: Dict) -> bool:
    """보이는 제목에 한글이 없다. CVE 번호뿐이거나 비어 있으면 설명이 있어야 제목을 지을 수 있다."""
    t = shown_title(state)
    if has_hangul(t):
        return False
    if is_cve_id_only(t) or not meaningful(t):
        return bool(meaningful(state.get("description")) or meaningful(state.get("desc_ko")))
    return True


def needs_desc(state: Dict) -> bool:
    return looks_english(shown_desc(state))


def wants(state: Dict) -> bool:
    return needs_title(state) or needs_desc(state)


def tried(state: Dict) -> bool:
    """지금 규칙으로 이 제목을 보내 답을 받았지만 쓸 수 없었다 — 다시 보내지 않는다."""
    mark = state.get("ko_tried")
    return bool(mark) and rule_of(state) >= TITLE_RULE and mark == title_key(state)


# '제품 이름 + 취약점' — 끝의 '취약점'을 떼고 제품을 꾸미는 낱말을 지운 뒤에도 한글이 남지 않고,
# 영어로 적힌 유형(XSS · Injection · Use-After-Free …)도 없으면 유형이 없는 제목이다.
# 저장소 쿼리(TursoStore.get_title_regen_candidates)는 끝이 '취약점'인 제목만 꺼내고 판정은 여기서 한다.
GENERIC_SUFFIX = "취약점"
PRODUCT_WORDS = (
    "확장 프로그램", "구성 요소", "플러그인", "테마", "모듈", "커널", "드라이버", "서버", "클라이언트",
    "라이브러리", "펌웨어", "확장", "애플리케이션", "소프트웨어", "제품", "시스템", "장치", "라우터", "카메라",
    "컴포넌트", "패키지", "서비스", "프레임워크", "버전", "이전", "보안", "다수", "여러", "관련", "에서", "및", "의",
)
_EN_TYPE = re.compile(
    r"(?i)(?<![a-z])("
    r"xss|csrf|xsrf|ssrf|xxe|sqli|rce|lfi|rfi|idor|dos|ddos|redos|uaf|oob|crlf|ssti|toctou|mitm|"
    r"injection|overflow|underflow|over-?read|traversal|bypass|disclosure|leak|leakage|escalation|elevation|"
    r"execution|deserialization|redirect|redirection|use[- ]after[- ]free|null pointer|dereference|"
    r"race condition|spoofing|clickjacking|smuggling|forgery|cross[- ]site|scripting|denial|"
    r"out[- ]of[- ]bounds|double[- ]free|format string|hard-?coded|cleartext|plaintext|memory corruption|"
    r"type confusion|buffer|uninitiali[sz]ed|insecure|improper|incorrect|unauthenticated|unauthori[sz]ed|"
    r"arbitrary|privileges?|takeover|hijack|hijacking|poisoning|tampering|enumeration|brute[- ]force|"
    r"side[- ]channel|infinite loop|exhaustion|uncontrolled|prototype pollution|zip slip|file inclusion|"
    r"mass assignment|exposure|crash|deadlock|access control|weak|misconfiguration|fixation|symlink|"
    r"external entity|padding oracle|sandbox escape|container escape"
    r")(?![a-z])")


def _title_core(title) -> Optional[str]:
    t = str(title or "").strip()
    if not t.endswith(GENERIC_SUFFIX):
        return None
    core = t[:-len(GENERIC_SUFFIX)]
    for word in PRODUCT_WORDS:
        core = core.replace(word, "")
    return core


def is_generic_title(title) -> bool:
    core = _title_core(title)
    return core is not None and not has_hangul(core) and not _EN_TYPE.search(core)


def title_work(state: Dict) -> str:
    """'translate' — 한국어 제목이 없다 · 'regen' — 유형 없는 한국어 제목을 지금 규칙으로 아직 안 만들었다 · ''."""
    if needs_title(state):
        return "translate"
    if rule_of(state) < TITLE_RULE and is_generic_title(state.get("title_ko")):
        return "regen"
    return ""


# CWE 이름 — 화면이 쓰는 표(docs/js/cwe.js)와 MITRE 공식 이름(docs/js/cwe-data.js)을 그대로 읽는다.
# 제목의 유형 이름이 목록 칩 · 상세 '취약점 유형' 칸과 같은 말이 되게 한다. 못 읽으면 번호만 넣는다.
_JS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "js")
_RANK = {"V": 0, "B": 1, "M": 2, "C": 3, "P": 4}
_WORST = 5
_cwe_cache: Optional[Tuple[Dict[str, str], Dict[str, str], Dict[str, int]]] = None


def _cwe_tables() -> Tuple[Dict[str, str], Dict[str, str], Dict[str, int]]:
    global _cwe_cache
    if _cwe_cache is not None:
        return _cwe_cache
    gloss: Dict[str, str] = {}
    official: Dict[str, str] = {}
    rank: Dict[str, int] = {}
    try:
        with open(os.path.join(_JS_DIR, "cwe.js"), encoding="utf-8") as f:
            for m in re.finditer(r"'(CWE-\d+)':\s*\['((?:[^'\\]|\\.)*)'", f.read()):
                gloss[m.group(1)] = m.group(2).replace("\\'", "'")
    except OSError:
        pass
    try:
        with open(os.path.join(_JS_DIR, "cwe-data.js"), encoding="utf-8") as f:
            m = re.search(r"^\s*const data = (\{.*\});\s*$", f.read(), re.MULTILINE)
        data = json.loads(m.group(1)) if m else {}
        for num, value in (data.get("w") or {}).items():
            level, _, name = str(value).partition("|")
            official[f"CWE-{num}"] = name
            rank[f"CWE-{num}"] = _RANK.get(level, _WORST)
        for num, name in (data.get("c") or {}).items():
            official.setdefault(f"CWE-{num}", str(name))
    except (OSError, ValueError, AttributeError):
        pass
    _cwe_cache = (gloss, official, rank)
    return _cwe_cache


def cwe_label(cwe_id: str) -> str:
    """cwe.js typeOf 와 같은 순서 — Argus 표 → 공식 이름 따옴표 안 별칭 → 짧은 공식 이름 → ''."""
    gloss, official, _ = _cwe_tables()
    if cwe_id in gloss:
        return gloss[cwe_id]
    en = official.get(cwe_id, "")
    if not en or en.upper().startswith("DEPRECATED:"):
        return ""
    alias = re.search(r"\('([^']+)'\)\s*$", en)
    if alias:
        return alias.group(1)
    if en.startswith("Path Traversal:"):
        return "Path Traversal"
    return en if len(en) <= 80 else ""


def cwe_hint(cwes, limit: int = 2) -> str:
    """'CWE-89 SQL 인젝션, CWE-200 정보 노출' — 구체적인 약점(Variant › Base › …)부터."""
    ids = []
    for value in cwes if isinstance(cwes, list) else []:
        m = re.match(r"^CWE-(\d+)$", str(value or "").strip(), re.IGNORECASE)
        if m and f"CWE-{m.group(1)}" not in ids:
            ids.append(f"CWE-{m.group(1)}")
    _, _, rank = _cwe_tables()
    ids.sort(key=lambda i: rank.get(i, _WORST))
    parts = []
    for cwe_id in ids[:limit]:
        label = cwe_label(cwe_id)
        parts.append(f"{cwe_id} {label}" if label else cwe_id)
    return ", ".join(parts)


def product_of(state: Dict) -> str:
    """첫 번째 영향 제품 — collector 가 출처에 제목이 없을 때 짓는 규칙과 같다(벤더가 제품 이름에 있으면 뺀다)."""
    for a in state.get("affected") or []:
        if not isinstance(a, dict):
            continue
        product = meaningful(a.get("product"))
        if not product:
            continue
        vendor = meaningful(a.get("vendor"))
        if vendor and vendor.split()[0].lower() not in product.lower():
            return f"{vendor} {product}"
        return product
    return ""


def make_item(cve_id: str, state: Dict) -> Dict:
    work = title_work(state)
    title = str(state.get("title") or "").strip()
    return {
        "id": cve_id,
        "key": title_key(state),
        "title": title if meaningful(title) and not is_cve_id_only(title) else "",
        "description": str(state.get("description") or state.get("desc_ko") or "").strip(),
        "product": product_of(state),
        "cwe": cwe_hint(state.get("cwe")),
        "need_title": bool(work),
        "regen": work == "regen",
        "need_desc": needs_desc(state),
    }


TITLE_RULES = (
    "Title rules (title_ko):\n"
    "- Name the vulnerability type in the title (e.g., 원격 코드 실행, SQL 인젝션, 인증 우회, XSS, 서비스 거부).\n"
    "- If the Title does not state the type (it is missing, only a CVE ID, or only a product name), "
    "take the type from the Desc and CWE and write \"<product> <type> 취약점\".\n"
    "- Keep product, vendor and component names as written."
)


def _one_line(text) -> str:
    """줄바꿈이 섞이면 번호 목록이 흐트러진다 — 공백을 한 칸으로."""
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _fields(it: Dict, desc_limit: int) -> str:
    parts = [f"Title: {_one_line(it.get('title')) or '(none)'}"]
    if it.get("product"):
        parts.append(f"Product: {_one_line(it['product'])}")
    if it.get("cwe"):
        parts.append(f"CWE: {it['cwe']}")
    parts.append(f"Desc: {_one_line(it.get('description'))[:desc_limit]}")
    return " / ".join(parts)


def batch_prompt(chunk) -> str:
    numbered = "\n".join(f"{n}. {_fields(it, 500)}" for n, it in enumerate(chunk, 1))
    return f"""You are a translator that outputs ONLY valid JSON. No markdown, no code fences, no commentary.
For EACH numbered CVE below, translate its Title into Korean following the title rules, and summarize its Description into Korean (each max 2 short lines).
{TITLE_RULES}
Keep technical terms in English or Korean transliteration (e.g., "버퍼 오버플로우", "SQL 인젝션") — do NOT translate them literally.
Output EXACTLY one JSON array with {len(chunk)} objects in the same order, and nothing else:
[{{"n":1,"title_ko":"...","desc_ko":"..."}}{',...' if len(chunk) > 1 else ''}]

CVEs:
{numbered}"""


def single_prompt(it: Dict) -> str:
    return f"""
Task: Translate Title and Summarize Description into Korean.
{TITLE_RULES}
[Input] {_fields(it, 1500)}
[Format]
제목: [Korean Title]
내용: [Korean Summary (Max 3 lines)]
Do NOT add intro/outro.
"""


def review(item: Dict, answer: Tuple[str, str]) -> Dict:
    """모델의 답 → 저장할 키. 쓸 수 있는 것만 쓰고, 하나라도 못 쓰면 '시도함'을 적는다.

    제목: 한글이 있고 CVE 번호뿐이 아니어야 한다. 유형 없는 제목을 다시 만드는 중이면 답도 유형이 있어야 한다.
    설명: 한글이 있어야 한다. 이미 한국어인 칸은 답으로 바꾸지 않는다.
    """
    title_new = str(answer[0] or "").strip()
    desc_new = str(answer[1] or "").strip()
    patch: Dict = {"ko_rule": TITLE_RULE}
    unusable = False
    if item["need_title"]:
        if (has_hangul(title_new) and not is_cve_id_only(title_new)
                and not (item["regen"] and is_generic_title(title_new))):
            patch["title_ko"] = title_new
        else:
            unusable = True
    if item["need_desc"]:
        if has_hangul(desc_new):
            patch["desc_ko"] = desc_new
        else:
            unusable = True
    if unusable:
        patch["ko_tried"] = item["key"]
    return patch
