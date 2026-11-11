import os
import sys
import json
import urllib.error
import datetime as dt
from typing import Optional
from collections import defaultdict

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import enrichment_sources
import pages
import risk
import rule_license
from fields import CWE_RE, meaningful
from rule_manager import LINK_ONLY_ENGINES, author_of
from store import create_store
from store.base import StoreError
from weekly_report import publish_weekly_report


_SINGLE_RULE_KEYS = ("sigma", "nuclei", "splunk", "yara")


def _flat_ssvc(state: dict) -> dict:
    nested = state.get("ssvc")
    if not isinstance(nested, dict):
        return {}
    out = {}
    for key in ("exploitation", "automatable", "technical_impact"):
        v = state.get(f"ssvc_{key}") or nested.get(key)
        if isinstance(v, str) and v.strip():
            out[f"ssvc_{key}"] = v.strip().lower()
    return out


def _verdict_of(state: dict, entry: dict):
    return risk.evaluate({
        **state,
        **_flat_ssvc(state),
        "is_kev": entry.get("is_kev", False),
        "cvss": entry.get("cvss", 0) or 0,
        "epss": entry.get("epss", 0) or 0,
    })


def _tier_of(state: dict, entry: dict, verdict=None) -> str:
    derived = (verdict or _verdict_of(state, entry)).tier
    stored = _s(state, "tier")
    if stored not in (risk.T0, risk.T1, risk.T2, risk.T3):
        return derived
    return min(stored, derived, key=risk.tier_rank)


_TRIGGER_ORDER = {key: i for i, key in enumerate(risk.TRIGGERS)}


def _triggers_of(state: dict, verdict) -> list:
    fired = [t for t in _l(state, "fired_triggers") if isinstance(t, str)]
    if fired:
        return fired
    return sorted(verdict.triggers, key=lambda k: _TRIGGER_ORDER.get(k, 99))


_EXPORT_SCHEMA = 4
_MAX_REFERENCES = 8
_ANALYSIS_KEYS = ("root_cause", "scenario", "impact")


def _analysis_of(state: dict, tier: str) -> dict:
    if tier not in risk.ALERTING_TIERS:
        return {}
    raw = state.get("analysis")
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key in _ANALYSIS_KEYS:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            out[key] = value.strip()
    steps = [s.strip() for s in (raw.get("mitigation") or [])
             if isinstance(s, str) and s.strip()]
    if steps:
        out["mitigation"] = steps[:6]
    return out


def _credited(rule, drop_code: bool = False):
    if isinstance(rule, list):
        return [_credited(r, drop_code) for r in rule]
    if not isinstance(rule, dict):
        return rule
    out = {k: v for k, v in rule.items() if not (drop_code and k == "code")}
    if not out.get("author") and rule.get("code"):
        found = author_of(rule["code"])
        if found:
            out["author"] = found
    # 라이선스 표기를 지금 표로 맞추고, 본문을 실을 수 없는 룰(라이선스를 확인하지 못한 YARA 등)은 본문을 뺀다.
    return rule_license.apply(out)


# EPSS 는 매일 모든 CVE 의 점수를 새로 발표한다. DB 의 점수는 그 CVE 를 다시 처리할 때, 그리고 상위 5% 일 때만
# 바뀌어(`pipeline.build_state` 의 epss_index 는 p95 이상만) 나머지는 옛 값이나 0(미채점)이 그대로 남는다 —
# 2026-09 실측: 추적 10,976건 전부 EPSS 파일에 있는데 2,313건이 0, 점수가 있는 8,663건 중 30% 가 최신 발표와 달랐다.
# 그래서 내보낼 때 전량 파일로 모든 행의 점수 · 백분위를 다시 채운다. 알림 판정에 쓰는 DB 값은 건드리지 않는다.
_EPSS_MIN_ROWS = 100_000   # 실제 파일은 38만 행 — 이보다 적으면 잘린 파일로 보고 쓰지 않는다


def refresh_epss(entries: list, epss) -> int:
    """전량 EPSS 로 점수 · 백분위를 다시 채운다. 파일에 없는 CVE 는 기존 값을 둔다(없다고 0 으로 만들지 않는다).
    파일이 없거나 너무 작으면 아무것도 바꾸지 않는다. 바뀐 행 수를 돌려준다."""
    if not epss or len(epss) < _EPSS_MIN_ROWS:
        return 0
    changed = 0
    for e in entries:
        hit = epss.get(str(e.get("id") or "").upper())
        if hit is None:
            continue
        score, pct = hit
        if e.get("epss") != score or e.get("epss_percentile") != pct:
            e["epss"], e["epss_percentile"] = score, pct
            changed += 1
    return changed


def normalize_rules(entries: list) -> int:
    """이월된 행까지 모든 행의 룰 표기를 맞춘다 — 증분 export 는 바뀐 행만 DB 에서 다시 읽기 때문이다.
    여러 번 적용해도 결과가 같다. 바뀐 행 수를 돌려준다."""
    changed = 0
    for e in entries:
        rules = e.get("rules")
        if not isinstance(rules, dict) or not rules:
            continue
        fixed = {k: _credited(v, drop_code=k in LINK_ONLY_ENGINES) for k, v in rules.items() if v}
        if fixed != rules:
            e["rules"] = fixed
            changed += 1
    return changed


def _get_db():
    try:
        return create_store()
    except Exception as e:
        print(f"  [!] 저장소 연결 실패: {e}", flush=True)
        return None


def _s(state: dict, key: str, default: str = "") -> str:
    v = state.get(key)
    return v if isinstance(v, str) else default


def _l(state: dict, key: str) -> list:
    v = state.get(key)
    return v if isinstance(v, list) else []


FACTS_FILE = "cve-facts.json"
_FACTS_SCHEMA = 1
_FACT_DESC_MAX = 4000
_NO_TEXT = ("해당 없음", "N/A", "정보 없음", "Error", "")


def facts_of(state: dict, title_origin: str, desc_origin: str) -> dict:
    out = {"o": [title_origin, desc_origin]}
    title = _s(state, "title").strip()
    if title not in _NO_TEXT:
        out["t"] = title
    desc = _s(state, "description").strip()
    if desc not in _NO_TEXT:
        out["d"] = desc if len(desc) <= _FACT_DESC_MAX else desc[:_FACT_DESC_MAX].rstrip() + "…"
    assigner = _s(state, "assigner").strip()
    if assigner:
        out["a"] = assigner
    sourced, seen = [], set()
    for aff in _l(state, "affected"):
        if not isinstance(aff, dict) or not _s(aff, "source").strip():
            continue
        vendor, product = _s(aff, "vendor", "Unknown"), _s(aff, "product", "Unknown")
        key = (vendor.strip().lower(), product.strip().lower())
        if key not in seen:
            seen.add(key)
            sourced.append([vendor, product, _s(aff, "source").strip()])
    if sourced:
        out["p"] = sourced
    return out


def export_cves(db, days: int = 90, since: str = None, facts: dict = None) -> list:
    rows = db.export_rows(since, days)
    result = []

    for row in rows:
        state = row.get("last_alert_state") or {}

        cwe_clean = []
        for w in _l(state, "cwe"):
            for m in CWE_RE.findall(str(w)):
                if m not in cwe_clean:
                    cwe_clean.append(m)

        title = _s(state, "title_ko") or _s(state, "title", "N/A")
        title_origin = "ai" if _s(state, "title_ko").strip() not in ("", _s(state, "title").strip()) else "source"
        if title.strip() in ("해당 없음", "N/A", "정보 없음", ""):
            aff0 = next((a for a in _l(state, "affected")
                         if isinstance(a, dict) and a.get("product")
                         and str(a["product"]).lower() not in ("n/a", "unknown")), None)
            if aff0:
                title = f"{aff0['product']} 취약점"
                title_origin = "argus"

        desc_ko = _s(state, "desc_ko").strip()
        desc_origin = "ai" if desc_ko and not _s(state, "description").strip().startswith(desc_ko) else "source"
        if facts is not None and row.get("id"):
            facts[row["id"]] = facts_of(state, title_origin, desc_origin)

        entry = {
            "id": row.get("id", ""),
            "title": title,
            "description": _s(state, "desc_ko") or _s(state, "description")[:300],
            "cvss": row.get("cvss_score", 0) or 0,
            "epss": row.get("epss_score", 0) or 0,
            "is_kev": bool(row.get("is_kev")),
            "cwe": cwe_clean,
            "affected": [],
            "date": row.get("last_alert_at") or row.get("updated_at") or "",
            "updated": row.get("updated_at") or "",
        }

        seen_aff = {}
        for aff in _l(state, "affected"):
            if not isinstance(aff, dict):
                continue
            vendor = _s(aff, "vendor", "Unknown")
            product = _s(aff, "product", "Unknown")
            versions = _s(aff, "versions")
            key = (vendor.strip().lower(), product.strip().lower())
            if key in seen_aff:
                prev = seen_aff[key]
                if versions and versions not in ("정보 없음", "") and versions not in prev["versions"]:
                    prev["versions"] = f"{prev['versions']}, {versions}" if prev["versions"] else versions
                continue
            item = {"vendor": vendor, "product": product, "versions": versions}
            seen_aff[key] = item
            entry["affected"].append(item)

        rules = row.get("rules_snapshot") or {}
        rule_engines = []
        for key in _SINGLE_RULE_KEYS:
            if rules.get(key):
                rule_engines.append(key)
        for net_rule in (rules.get("network") or []):
            engine = net_rule.get("engine") or "network"
            if engine not in rule_engines:
                rule_engines.append(engine)
        entry["rule_engines"] = rule_engines
        entry["has_official_rules"] = bool(row.get("has_official_rules"))
        if rule_engines:
            entry["rules"] = {
                k: _credited(rules[k], drop_code=k in LINK_ONLY_ENGINES)
                for k in _SINGLE_RULE_KEYS + ("network",) if rules.get(k)
            }

        state_poc = state.get("has_poc", False)
        entry["has_poc"] = state_poc
        entry["poc_urls"] = _l(state, "poc_urls")[:3]

        entry["cvss_vector"] = _s(state, "cvss_vector")
        entry["cvss_version"] = _s(state, "cvss_version")
        scores = state.get("cvss_scores")
        if isinstance(scores, dict) and len(scores) > 1:
            entry["cvss_alt"] = {k: v[0] for k, v in scores.items()
                                 if isinstance(v, (list, tuple)) and v}

        entry["ssvc_exploitation"] = state.get("ssvc_exploitation") or (state.get("ssvc") or {}).get("exploitation")
        entry["has_public_exploit"] = state.get("has_public_exploit", False)
        entry["has_metasploit_module"] = state.get("has_metasploit_module", False)
        entry["metasploit_modules"] = _l(state, "metasploit_modules")[:3]
        entry["has_nuclei_template"] = state.get("has_nuclei_template", False)
        entry["ai_discovered"] = state.get("ai_discovered", False)
        entry["ai_program"] = _s(state, "ai_program")
        entry["ai_detail"] = _s(state, "ai_detail")
        entry["ai_url"] = _s(state, "ai_url")
        entry["is_vulncheck_kev"] = state.get("is_vulncheck_kev", False)

        verdict = _verdict_of(state, entry)
        entry["tier"] = _tier_of(state, entry, verdict)
        entry["triggers"] = _triggers_of(state, verdict)
        entry["epss_percentile"] = state.get("epss_percentile") or 0

        ssvc = state.get("ssvc") or {}
        entry["ssvc_automatable"] = state.get("ssvc_automatable") or ssvc.get("automatable")
        entry["ssvc_technical_impact"] = state.get("ssvc_technical_impact") or ssvc.get("technical_impact")
        entry["is_kev_ransomware"] = state.get("is_kev_ransomware", False)
        entry["kev_due_date"] = _s(state, "kev_due_date")[:10]
        entry["nuclei_severity"] = _s(state, "nuclei_severity")

        for key in ("_exploit_db_url", "_nuclei_url"):
            url = _s(state, key)
            if url:
                entry[key] = url

        refs = []
        for ref in _l(state, "references"):
            url = ref if isinstance(ref, str) else _s(ref, "url")
            url = url.strip()
            if url.startswith(("http://", "https://")) and url not in refs:
                refs.append(url)
            if len(refs) >= _MAX_REFERENCES:
                break
        if refs:
            entry["references"] = refs

        analysis = _analysis_of(state, entry["tier"])
        if analysis:
            entry["analysis"] = analysis

        entry["published"] = _s(state, "published")[:10]

        entry["is_kernel"] = any(
            _s(a, "vendor").strip().lower() == "linux" for a in entry["affected"]
        )

        score = entry["cvss"]
        if score >= 9.0:
            entry["severity"] = "Critical"
        elif score >= 7.0:
            entry["severity"] = "High"
        elif score >= 4.0:
            entry["severity"] = "Medium"
        elif score > 0:
            entry["severity"] = "Low"
        else:
            entry["severity"] = "None"

        result.append(entry)

    return result


TABLE_AFFECTED = 3


def build_product_index(entries: list) -> dict:
    vend, prod, vers = {}, {}, {}


    def idx(table, value):
        value = (value or "").strip()
        if not value:
            return -1
        if value not in table:
            table[value] = len(table)
        return table[value]

    mapping = {}
    for e in entries:
        items = [[idx(vend, a.get("vendor")), idx(prod, a.get("product")),
                  idx(vers, a.get("versions"))]
                 for a in (e.get("affected") or []) if isinstance(a, dict)]
        if items:
            mapping[e.get("id", "")] = items
    return {
        "vendors": list(vend), "products": list(prod), "versions": list(vers),
        "map": mapping,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def decode_product_index(index: dict) -> dict:
    v, p, s = (index.get("vendors") or [], index.get("products") or [],
               index.get("versions") or [])


    def at(table, i):
        return table[i] if isinstance(i, int) and 0 <= i < len(table) else ""

    out = {}
    for cve, items in (index.get("map") or {}).items():
        out[cve] = [{"vendor": at(v, it[0]), "product": at(p, it[1]),
                     "versions": at(s, it[2])}
                    for it in items if isinstance(it, list) and len(it) >= 3]
    return out


def live_ids(db, days: int = 90):
    try:
        return db.live_ids(days)
    except StoreError as e:
        print(f"  [!] id 목록 조회 실패({e}) → 이번 회차는 병합에서 제외하지 않는다",
              flush=True)
        return None


_FULL_EXPORT_MAX_AGE_H = 24


def _full_export_requested(db) -> bool:
    """전량 export 요청이 있는가 — 읽기만 한다. 파일을 다 쓴 뒤 _clear_full_export 가 지운다.

    시작할 때 지우면 export 가 도중에 죽었을 때 요청이 사라져 백필 결과가 화면에 반영되지 않았다.
    """
    try:
        return db.has_full_export_flag()
    except StoreError as e:
        print(f"  전량 export 표시 확인 실패(무시): {e}", flush=True)
        return False


def _clear_full_export(db) -> None:
    try:
        db.clear_full_export_flag()
    except StoreError as e:
        print(f"  전량 export 표시를 지우지 못함(다음 회차도 전량): {e}", flush=True)


def fetch_live_products() -> Optional[dict]:
    """배포된 제품 인덱스 — 읽지 못하면 None (빈 dict 는 '읽었는데 비어 있음')."""
    try:
        payload = pages.fetch_published_json("cve-products.json", timeout=180)
        if not isinstance(payload, dict) or not isinstance(payload.get("map"), dict):
            return None
        return decode_product_index(payload)
    except Exception as e:
        print(f"  직전 제품 인덱스를 읽지 못함({e})", flush=True)
        return None


def fetch_live_facts() -> tuple:
    try:
        payload = pages.fetch_published_json(FACTS_FILE, timeout=180)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, "missing"
        print(f"  직전 원문 사실 파일을 읽지 못함({e})", flush=True)
        return None, "error"
    except Exception as e:
        print(f"  직전 원문 사실 파일을 읽지 못함({e})", flush=True)
        return None, "error"
    if payload is None:
        return None, "error"
    if not isinstance(payload, dict) or payload.get("schema") != _FACTS_SCHEMA \
            or not isinstance(payload.get("facts"), dict):
        return None, "missing"
    return payload["facts"], "ok"


def write_compact_json(path: str, payload) -> None:
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def merge_facts(cve_data: list, fresh: dict, carried: dict, fresh_ids: set) -> dict:
    out = {}
    for e in cve_data:
        cid = e.get("id")
        if not cid:
            continue
        f = fresh.get(cid) if cid in fresh_ids else (carried.get(cid) or fresh.get(cid))
        if f:
            out[cid] = f
    return out


def _fetch_live_export() -> tuple:
    try:
        rows = pages.fetch_published_json("cves.json", timeout=180)
        stats = pages.fetch_published_json("stats.json", timeout=180)
        generated_at = (stats or {}).get("generated_at")
        if isinstance(rows, list) and rows and generated_at:
            print(f"  직전 export를 배포본에서 읽음 ({len(rows)}건)", flush=True)
            return rows, generated_at, stats.get("schema")
    except Exception as e:
        print(f"  배포본을 읽지 못함({e}) → 체크아웃 사본 확인", flush=True)
    return None, None, None


def load_previous_export(data_dir: str) -> tuple:
    if os.environ.get("ARGUS_FULL_EXPORT") == "1":
        print("  ARGUS_FULL_EXPORT=1 → 전량 export", flush=True)
        return None, None
    try:
        rows, generated_at, schema = _fetch_live_export()
        if rows is None:
            with open(os.path.join(data_dir, "cves.json"), encoding="utf-8") as f:
                rows = json.load(f)
            with open(os.path.join(data_dir, "stats.json"), encoding="utf-8") as f:
                stats = json.load(f)
            generated_at, schema = stats.get("generated_at"), stats.get("schema")
        if not isinstance(rows, list) or not rows or not generated_at:
            return None, None
        if schema != _EXPORT_SCHEMA:
            print(f"  직전 export 스키마 {schema} ≠ 현재 {_EXPORT_SCHEMA} → 전량 export",
                  flush=True)
            return None, None
        if not any(r.get("updated") for r in rows[:50]):
            print("  직전 파일에 병합 기준(updated)이 없음 → 전량 export", flush=True)
            return None, None
        prev = dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
        age_h = (dt.datetime.now(dt.timezone.utc) - prev).total_seconds() / 3600
        if age_h > _FULL_EXPORT_MAX_AGE_H:
            print(f"  직전 export가 {age_h:.0f}시간 전 → 전량 export로 재동기화", flush=True)
            return None, None
        return rows, (prev - dt.timedelta(minutes=10)).isoformat()
    except Exception as e:
        print(f"  직전 export를 읽지 못함({e}) → 전량 export", flush=True)
        return None, None


def merge_exports(previous: list, fresh: list, days: int = 90, keep=None) -> list:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    by_id = {r.get("id"): r for r in previous if r.get("id")}
    for r in fresh:
        if r.get("id"):
            by_id[r["id"]] = r
    if keep is not None:
        dropped = [k for k in by_id if k not in keep]
        for k in dropped:
            del by_id[k]
        if dropped:
            print(f"  DB 에서 사라진 {len(dropped):,}건을 병합에서 제외", flush=True)
    merged = [r for r in by_id.values() if (r.get("updated") or "") >= cutoff]
    merged.sort(key=lambda r: r.get("updated") or "", reverse=True)
    return merged


def export_stats(cve_data: list) -> dict:
    now = dt.datetime.now(dt.timezone.utc)

    severity_counts = defaultdict(int)
    vendor_counts = defaultdict(int)
    product_counts = defaultdict(int)
    product_vendor = {}
    daily_counts = defaultdict(int)
    recent_24h = 0
    kev_count = 0
    kernel_count = 0


    for cve in cve_data:
        severity_counts[cve.get("severity", "None")] += 1

        if cve.get("is_kev"):
            kev_count += 1

        pub = (cve.get("published") or "")[:10]
        if pub:
            daily_counts[pub] += 1

        date_str = cve.get("date", "")
        if date_str:
            try:
                cve_dt = dt.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if (now - cve_dt).total_seconds() < 86400:
                    recent_24h += 1
            except (ValueError, TypeError):
                pass

        if cve.get("is_kernel"):
            kernel_count += 1
            continue

        seen_v, seen_p = set(), set()
        for aff in cve.get("affected", []):
            vendor, product = meaningful(aff.get("vendor")), meaningful(aff.get("product"))
            if vendor and vendor not in seen_v:
                vendor_counts[vendor] += 1
                seen_v.add(vendor)
            if product and product not in seen_p:
                product_counts[product] += 1
                seen_p.add(product)
                if vendor:
                    product_vendor.setdefault(product, vendor)

    today = now.date()
    daily_trend = []
    for i in range(29, -1, -1):
        day = (today - dt.timedelta(days=i)).isoformat()
        daily_trend.append((day, daily_counts.get(day, 0)))

    trend_covered = sum(daily_counts.values())

    product_top = sorted(product_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    vendor_top = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "generated_at": now.isoformat(),
        "schema": _EXPORT_SCHEMA,
        "triggers": {key: t.label for key, t in risk.TRIGGERS.items()},
        "cve": {
            "total": len(cve_data),
            "recent_24h": recent_24h,
            "kev_count": kev_count,
            "kernel_count": kernel_count,
            "severity": dict(severity_counts),
            "daily_trend": [{"date": d, "count": c} for d, c in daily_trend],
            "trend_covered": trend_covered,
            "top_products": [{"product": p, "vendor": product_vendor.get(p, ""), "count": c}
                             for p, c in product_top],
            "top_vendors": [{"vendor": v, "count": c} for v, c in vendor_top],
        },
    }


def _is_alerting_row(row: dict) -> bool:
    state = row.get("last_alert_state") or {}
    entry = {"is_kev": bool(row.get("is_kev") or state.get("is_kev")),
             "cvss": row.get("cvss_score") or 0, "epss": row.get("epss_score") or 0}
    return risk.is_alerting(_tier_of(state, entry))


RETENTION_BATCH = 1000


def _doomed(rows: list) -> list:
    return [r["id"] for r in rows if r.get("id") and not _is_alerting_row(r)]


RETENTION_PAGES = 10


def _retire(db, before: str, act, **filters) -> tuple:
    """기준일보다 오래된 행을 쪽 단위로 훑어 지울 것만 act 에 넘긴다 — (처리한 수, 남긴 수).

    남기는 행(악용 중)은 다음 쪽에서 건너뛴다. 첫 쪽만 보면 남는 행이 그 쪽을 다 채웠을 때
    뒤에 있는 행은 영영 정리되지 않았다.
    """
    done = kept = 0
    for _ in range(RETENTION_PAGES):
        rows = db.retention_rows(before, RETENTION_BATCH, offset=kept, **filters)
        doomed = _doomed(rows)
        done += act(doomed) or 0
        kept += len(rows) - len(doomed)
        if len(rows) < RETENTION_BATCH:
            break
    return done, kept


def apply_retention_policy(db, days: int = 120, marker_days: int = 30,
                           delete_days: int = 180, watch_days: int = 90,
                           max_rows: int = 20000) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    batch = RETENTION_BATCH

    def cutoff(n):
        return (now - dt.timedelta(days=n)).isoformat()

    cleaned, _ = _retire(db, cutoff(days), db.blank_states, tracked=True)

    deleted_count = db.delete_markers(cutoff(marker_days), batch)
    if deleted_count:
        print(f"  구 마커 {deleted_count}건 청소 ({marker_days}일 경과)", flush=True)

    watch_count, kept = _retire(db, cutoff(watch_days), db.delete_rows, unalerted=True)
    if watch_count or kept:
        print(f"  관찰 {watch_count}건 만료 삭제 ({watch_days}일간 신호 없음)"
              f"{f' · 악용 중이라 보존 {kept}건' if kept else ''}", flush=True)

    purged_count, _ = _retire(db, cutoff(delete_days), db.delete_rows)
    if purged_count:
        print(f"  오래된 행 {purged_count}건 삭제 ({delete_days}일 경과)", flush=True)

    capped = 0
    tracked_now = _count(db, tracked=True)
    if tracked_now > max_rows:
        excess = tracked_now - max_rows
        over = db.retention_rows(cutoff(watch_days), min(excess * 2, batch),
                                 oldest_first=True)
        capped = db.delete_rows(_doomed(over)[:excess])
        if capped < excess:
            print(f"  ⚠️ 추적 {tracked_now:,}행 > 상한 {max_rows:,} 이지만 "
                  f"{capped:,}건만 지울 수 있다 — 나머지는 {watch_days}일 안이거나 "
                  f"악용 중이라 보존한다. 물량이 계속 늘면 risk.py 임계를 조여야 한다",
                  flush=True)
        elif capped:
            print(f"  상한 초과 {capped:,}건 삭제 (추적 상한 {max_rows:,}행)", flush=True)

    tracked = _count(db, tracked=True)
    remaining = _count(db)
    print(f"  현황: 전체 {remaining:,} · 추적 {tracked:,} · 상태없음 {remaining - tracked:,} "
          f"· 이번 삭제 {deleted_count + watch_count + purged_count + capped:,}", flush=True)

    return cleaned


def _count(db, tracked: bool = False) -> int:
    try:
        return db.count_rows(tracked=tracked)
    except StoreError as e:
        print(f"  [!] 행 수 조회 실패(무시): {e}", flush=True)
        return 0


def main(data_dir: str = None):
    print("=== Dashboard Data Export ===", flush=True)
    db = _get_db()

    data_dir = data_dir or os.path.join(os.path.dirname(_THIS_DIR), "docs", "data")
    os.makedirs(data_dir, exist_ok=True)

    if db is None:
        # 빈 cves.json · stats.json 을 쓰면 배포 단계가 '이번 실행 생성분'으로 보고 대시보드를 비운다.
        # 아무것도 쓰지 않고 실패로 끝내면 배포 단계가 직전 배포본을 그대로 이어받는다.
        print("  [!] 저장소에 연결하지 못함 → 파일을 쓰지 않는다 (배포본 유지)", flush=True)
        raise SystemExit(1)

    print("[1/4] CVE 데이터 export...", flush=True)
    full_requested = _full_export_requested(db)
    if full_requested:
        print("  백필 반영 요청 있음 → 이번은 전량 export", flush=True)
        previous, since = None, None
    else:
        previous, since = load_previous_export(data_dir)
    carried = {}
    if previous is not None:
        carried = fetch_live_products()
        if carried is None:
            # 직전 인덱스 없이 병합하면 이번에 바뀌지 않은 CVE 의 제품이 표에 실린 3개로 줄어든 채 굳는다.
            print("  직전 제품 인덱스를 읽지 못함 → 이번은 전량 export 로 다시 만든다", flush=True)
            previous, since, carried = None, None, {}
    carried_facts, facts_status = {}, "ok"
    if previous is not None:
        carried_facts, facts_status = fetch_live_facts()
        if facts_status == "missing":
            print(f"  배포본에 {FACTS_FILE} 가 없음 → 이번은 전량 export 로 채운다", flush=True)
            previous, since = None, None
        carried_facts = carried_facts or {}
    fresh_facts = {}
    fresh_ids = set()
    if previous is None:
        cve_data = export_cves(db, facts=fresh_facts)
        print(f"  전량 export: {len(cve_data)}건", flush=True)
    else:
        fresh = export_cves(db, since=since, facts=fresh_facts)
        fresh_ids = {r.get("id") for r in fresh if r.get("id")}
        cve_data = merge_exports(previous, fresh, keep=live_ids(db))
        print(f"  증분 export: 변경 {len(fresh)}건 → 병합 후 {len(cve_data)}건 "
              f"(직전 {len(previous)}건)", flush=True)
    merged_products = []
    restored = 0
    for e in cve_data:
        aff = e.get("affected") or []
        if e.get("id") not in fresh_ids:
            full = carried.get(e.get("id")) or []
            if len(full) > len(aff):
                restored += len(full) - len(aff)
                aff = full
                e["affected"] = aff
        merged_products.append({"id": e.get("id"), "affected": aff})
    if restored:
        print(f"  직전 인덱스에서 제품 항목 {restored:,}개 이어받음", flush=True)

    prod_index = build_product_index(merged_products)
    prod_path = os.path.join(data_dir, "cve-products.json")
    pages.write_json(prod_path, prod_index)
    total_items = sum(len(v) for v in prod_index["map"].values())
    print(f"  영향 제품 인덱스: {len(prod_index['map']):,}건 · 항목 {total_items:,}개 "
          f"(고유 제품 {len(prod_index['products']):,}) → {prod_path}", flush=True)

    for e in cve_data:
        aff = e.get("affected") or []
        if len(aff) > TABLE_AFFECTED:
            e["affected"] = aff[:TABLE_AFFECTED]
    relabeled = normalize_rules(cve_data)
    if relabeled:
        print(f"  룰 라이선스 표기를 맞춤: {relabeled:,}건", flush=True)
    epss = enrichment_sources.load_epss_full()
    if not epss or len(epss) < _EPSS_MIN_ROWS:
        print(f"  EPSS 전량 파일을 쓰지 못함({len(epss or {}):,}행) → 점수는 DB 값 그대로", flush=True)
    else:
        print(f"  EPSS 점수를 전량 파일({len(epss):,}행)로 맞춤: {refresh_epss(cve_data, epss):,}건 바뀜", flush=True)

    cve_path = os.path.join(data_dir, "cves.json")
    pages.write_json(cve_path, cve_data)
    print(f"  CVE: {len(cve_data)}건 → {cve_path}", flush=True)

    if previous is None or facts_status == "ok":
        facts = merge_facts(cve_data, fresh_facts, carried_facts,
                            fresh_ids if previous is not None else set(fresh_facts))
        facts_path = os.path.join(data_dir, FACTS_FILE)
        write_compact_json(facts_path, {
            "schema": _FACTS_SCHEMA,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "facts": facts,
        })
        print(f"  원문 사실(제목·설명 원문 · CNA · 제품 출처): {len(facts):,}건 → {facts_path}", flush=True)
    else:
        print(f"  {FACTS_FILE} 는 이번 회차에 쓰지 않는다 → 배포 단계가 배포본을 이월", flush=True)

    print("[2/4] 통계 집계...", flush=True)
    stats = export_stats(cve_data)
    stats_path = os.path.join(data_dir, "stats.json")
    pages.write_json(stats_path, stats)
    print(f"  Stats → {stats_path}", flush=True)
    if full_requested:
        _clear_full_export(db)

    print("[3/4] 주간 리포트 확인...", flush=True)
    try:
        publish_weekly_report(cve_data)
    except Exception as e:
        print(f"  [!] 주간 리포트 생성 실패(무시): {e}", flush=True)

    print("[4/4] DB 보존 정책 적용...", flush=True)
    try:
        cleaned = apply_retention_policy(db)
        print(f"  {cleaned}건 정리 (rules_snapshot/last_alert_state null 처리)", flush=True)
    except Exception as e:
        print(f"  [!] DB 보존 정책 적용 실패: {e}", flush=True)

    print("=== Export 완료 ===", flush=True)


if __name__ == "__main__":
    main()
