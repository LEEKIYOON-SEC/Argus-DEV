import datetime
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import pytz
from google import genai
from google.genai import types

import ai_provenance
import enrichment_sources
import feed
import package_index
import pipeline
import risk
import rule_refresh
import signal_snapshot
import state as pstate
from pages import cve_url as _cve_url
from pages import dashboard_url as _dashboard_url
from collector import Collector
from config import config
from store import Store, create_store
from logger import logger
from notifier import SlackNotifier
from rate_limiter import (gemini_backoff, gemini_error_kind, rate_limit_manager)
from report import make_analysis
from rule_manager import RuleManager
from rule_manager import grown as rule_manager_grown
from rule_manager import index_ok as rule_manager_index_ok

KST = pytz.timezone('Asia/Seoul')

try:
    gemini_client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
        http_options=types.HttpOptions(timeout=120_000),
    )
except Exception:
    gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))


def _looks_english(text: str) -> bool:
    t = (text or '').strip()
    if not t or t in ("N/A", "-"):
        return False
    if re.search(r'[가-힣]', t):
        return False
    return len(re.findall(r'[A-Za-z]', t)) >= 8


_TOKENS_PER_ITEM = 250


def _translation_budget() -> int:
    batch = max(1, config.PERFORMANCE["translation_batch_size"])
    reserve = config.PERFORMANCE["translation_daily_reserve"]
    minutes = config.PERFORMANCE["translation_minutes"]

    best = 0
    for _model, key in _TRANSLATION_STAGES:
        allowed = int(rate_limit_manager.daily_headroom(key) * (1 - reserve)) * batch
        tpm = rate_limit_manager.minute_token_headroom(key)
        if tpm:
            allowed = min(allowed, (tpm // _TOKENS_PER_ITEM) * minutes)
        best = max(best, allowed)
    return max(0, best)


def translate_tracked(db: Store, deadline_ts: float) -> int:
    stop_ts = min(deadline_ts,
                  time.time() + config.PERFORMANCE["translation_minutes"] * 60)
    if time.time() > stop_ts:
        logger.info("번역 생략 (시간 예산 도달)")
        return 0
    budget = _translation_budget()
    if budget <= 0:
        logger.warning("번역 생략 — 번역 모델의 일일 한도(RPD)가 남아 있지 않다")
        return 0

    pool = max(1, config.PERFORMANCE["translation_backfill_pool"])
    total = db.count_tracked()
    logger.info(f"🈯 번역 예산: 최대 {budget:,}건 · {(stop_ts - time.time()) / 60:.0f}분 "
                f"(추적 {total:,}행)")

    done = 0
    scanned_total = 0
    max_windows = (total // pool + 2) if total else 25
    try:
        while done < budget and time.time() < stop_ts and max_windows > 0:
            max_windows -= 1
            offset = pstate.read_backfill_offset()
            if total and offset >= total:
                offset = 0
            candidates = db.get_translation_backfill_candidates(limit=pool, offset=offset)
            if not candidates:
                logger.info(f"번역: 후보 없음 (스캔 {offset:,}/{total:,}행 — 다음 실행도 "
                            f"{offset:,}부터. 조회 실패였다면 여기서 다시 본다)")
                break

            items = []
            scanned = 0
            for row in candidates:
                scanned += 1
                state = row.get('last_alert_state') or {}
                title_ko = state.get('title_ko') or state.get('title') or ''
                desc_ko = state.get('desc_ko') or state.get('description') or ''
                if not (_looks_english(title_ko) or _looks_english(desc_ko)):
                    continue
                items.append({"id": row['id'],
                              "title": state.get('title') or title_ko,
                              "description": (state.get('description')
                                              or state.get('desc_ko') or '')})
                if len(items) >= budget - done:
                    break

            next_offset = offset + scanned
            wrapped = bool(total and next_offset >= total) or len(candidates) < pool
            pstate.write_backfill_offset(0 if wrapped else next_offset)
            scanned_total += scanned

            if items:
                logger.info(f"🈯 영문 {len(items)}건 처리 "
                            f"(스캔 {offset:,}~{offset + scanned:,}/{total:,}행)")
                translations = generate_korean_summaries_batch(items, deadline_ts=stop_ts)
                for it in items:
                    tr = translations.get(it['id'])
                    if not tr or _looks_english(tr[0]):
                        continue
                    if db.update_translation(it['id'], tr[0], tr[1]):
                        done += 1

            if _translation_exhausted():
                logger.warning("번역 중단 — 일일 한도(RPD/TPD) 소진. 남은 대상은 한도가 "
                               "풀린 뒤 다음 회차가 이어받는다 (창 위치는 저장돼 있다)")
                break
            if wrapped:
                logger.info("번역: 전체를 한 바퀴 돌았다 — 다음 회차는 처음부터")
                break
    except Exception as e:
        logger.warning(f"번역 중단(오류): {e}")

    if done:
        db.request_full_export()
    logger.info(f"🈯 번역 완료: {done:,}건 한글화 · {scanned_total:,}행 스캔 · "
                f"{'다음 export는 전량' if done else '변경 없음'}")
    return done


def _translation_exhausted() -> bool:
    return all(rate_limit_manager.is_rpd_exhausted(key)
               for _model, key in _TRANSLATION_STAGES)


_NO_AFC = types.AutomaticFunctionCallingConfig(disable=True)

_TRANSLATION_STAGES = config.TRANSLATION_MODELS

_TR_STAGE_ADVANCE = ("skip", "rate", "transient")


def generate_korean_summary(cve_data: Dict, retry_on_transient: bool = False) -> Tuple[str, str]:
    prompt = f"""
Task: Translate Title and Summarize Description into Korean.
[Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
[Format]
제목: [Korean Title]
내용: [Korean Summary (Max 3 lines)]
Do NOT add intro/outro.
"""

    fallback = (cve_data['title'], cve_data['description'][:200])
    max_attempts = 3 if retry_on_transient else 1

    reason = "skip"
    for model, limiter_key in _TRANSLATION_STAGES:
        out, reason = _translate_one(prompt, fallback, model, limiter_key, max_attempts)
        if out is not None:
            _tr_bump("ok")
            return out
        if reason not in _TR_STAGE_ADVANCE:
            break
    _tr_bump(_TR_REASON_KEY.get(reason, "en_other"))
    return fallback


def _translate_one(prompt: str, fallback: Tuple[str, str], model: str, limiter_key: str,
                   max_attempts: int) -> Tuple[Optional[Tuple[str, str]], str]:
    for attempt in range(1, max_attempts + 1):
        try:
            if not rate_limit_manager.check_and_wait(limiter_key):
                return None, "skip"
            response = gemini_client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=1024,
                    temperature=0.3,
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )],
                    automatic_function_calling=_NO_AFC,
                )
            )
            gemini_tokens = 0
            usage = getattr(response, "usage_metadata", None)
            if usage is not None:
                gemini_tokens = getattr(usage, "total_token_count", 0) or 0
            rate_limit_manager.record_call(limiter_key, tokens_used=gemini_tokens)

            text = (response.text or "").strip()
            title_ko, desc_ko = fallback

            for line in text.split('\n'):
                if line.startswith("제목:"):
                    title_ko = line.replace("제목:", "").strip()
                if line.startswith("내용:"):
                    desc_ko = line.replace("내용:", "").strip()

            return (title_ko, desc_ko), "ok"

        except Exception as e:
            msg = str(e)
            kind = _gemini_error_kind(msg)
            if kind == "rpd":
                rate_limit_manager.mark_rpd_exhausted(limiter_key)
                logger.warning(f"번역 일일 한도(RPD) 소진: {model}")
                return None, "skip"
            if kind in ("rate", "transient") and attempt < max_attempts:
                wait = _gemini_backoff(kind, attempt, msg)
                logger.warning(f"번역 {kind} 오류({model} {attempt}/{max_attempts}): {e} → {wait:.0f}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"번역 실패({model} {kind}): {e}")
            return None, kind

    return None, "transient"


_gemini_backoff = gemini_backoff


_gemini_error_kind = gemini_error_kind


_TR_LOCK = threading.Lock()
_TR_STATS: Dict[str, int] = {}
_TR_LABELS = [("en_rpd", "일일한도"), ("en_rate", "분당한도"), ("en_transient", "서버오류"),
              ("en_deadline", "시간초과"), ("en_other", "기타")]
_TR_REASON_KEY = {"skip": "en_rpd", "rate": "en_rate", "transient": "en_transient",
                  "other": "en_other"}


def _tr_bump(key: str, n: int = 1) -> None:
    if n <= 0:
        return
    with _TR_LOCK:
        _TR_STATS[key] = _TR_STATS.get(key, 0) + n


def _log_translation_summary() -> None:
    with _TR_LOCK:
        snap = dict(_TR_STATS)
    ok = snap.get("ok", 0)
    fallback = sum(snap.get(k, 0) for k, _ in _TR_LABELS)
    if not (ok or fallback):
        return
    breakdown = " · ".join(f"{label} {snap.get(key, 0)}" for key, label in _TR_LABELS)
    rpd = " · ".join(
        f"{model} {u:,}/{l:,}"
        for model, u, l in ((m,) + rate_limit_manager.rpd_status(k) for m, k in _TRANSLATION_STAGES)
    )
    logger.info(f"🈯 번역 요약(누적): 한글 {ok}건 · 영문폴백 {fallback}건 "
                f"({breakdown}) · RPD {rpd}")


def generate_korean_summaries_batch(items: List[Dict],
                                    deadline_ts: Optional[float] = None) -> Dict[str, Tuple[str, str]]:
    results: Dict[str, Tuple[str, str]] = {}
    if not items:
        return results

    batch_size = config.PERFORMANCE["translation_batch_size"]
    chunks = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    total_chunks = len(chunks)
    concurrency = max(1, config.PERFORMANCE["translation_concurrency"])
    logger.info(f"번역: {len(items)}건 → 배치 {total_chunks}청크 "
                f"(배치 {batch_size}건, 동시 {concurrency}콜)")
    started = time.time()
    lock = threading.Lock()
    state = {"done": 0, "deadline_warned": False, "fell_back": 0}


    def _individual(it: Dict, allow_retry: bool) -> Tuple[str, str]:
        return generate_korean_summary(
            {"title": it['title'], "description": it['description']},
            retry_on_transient=allow_retry)


    def _do_chunk(chunk: List[Dict]) -> Dict[str, Tuple[str, str]]:
        out: Dict[str, Tuple[str, str]] = {}
        if deadline_ts is not None and time.time() > deadline_ts:
            with lock:
                if not state["deadline_warned"]:
                    logger.warning(f"⏰ 번역 시간 예산 도달 — 잔여 ~{total_chunks - state['done']}청크 영문 폴백")
                    state["deadline_warned"] = True
            for it in chunk:
                out[it['id']] = (it['title'], (it['description'] or '')[:200])
            _tr_bump("en_deadline", len(chunk))
            return out
        try:
            parsed, reason = _translate_chunk(chunk, retry_on_transient=True)
            if parsed is not None:
                out.update(parsed)
                _tr_bump("ok", len(chunk))
            elif reason == "parse":
                with lock:
                    state["fell_back"] += len(chunk)
                for it in chunk:
                    out[it['id']] = _individual(it, allow_retry=True)
            else:
                for it in chunk:
                    out[it['id']] = (it['title'], (it['description'] or '')[:200])
                _tr_bump(_TR_REASON_KEY.get(reason, "en_other"), len(chunk))
        except Exception as e:
            logger.warning(f"번역 청크 실패 → 영문 폴백: {e}")
            for it in chunk:
                out.setdefault(it['id'], (it['title'], (it['description'] or '')[:200]))
            _tr_bump("en_other", len(chunk))
        with lock:
            state["done"] += 1
            done = state["done"]
        if done % 5 == 0 or done == total_chunks:
            logger.info(f"번역 진행: {done}/{total_chunks} 청크 ({time.time() - started:.0f}초)")
        return out

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for out in ex.map(_do_chunk, chunks):
            results.update(out)

    if state["fell_back"]:
        logger.info(f"번역: 배치 응답 형식 파손 {state['fell_back']}건 → 개별 번역으로 재시도")
    _log_translation_summary()
    return results


def _translate_chunk(chunk: List[Dict],
                     retry_on_transient: bool) -> Tuple[Optional[Dict[str, Tuple[str, str]]], str]:
    numbered = "\n".join(
        f"{n}. Title: {it['title']} / Desc: {(it['description'] or '')[:500]}"
        for n, it in enumerate(chunk, 1)
    )
    prompt = f"""You are a translator that outputs ONLY valid JSON. No markdown, no code fences, no commentary.
For EACH numbered CVE below, translate its Title into Korean and summarize its Description into Korean (each max 2 short lines).
Keep technical terms in English or Korean transliteration (e.g., "버퍼 오버플로우", "SQL 인젝션") — do NOT translate them literally.
Output EXACTLY one JSON array with {len(chunk)} objects in the same order, and nothing else:
[{{"n":1,"title_ko":"...","desc_ko":"..."}}{',...' if len(chunk) > 1 else ''}]

CVEs:
{numbered}"""
    max_attempts = 3 if retry_on_transient else 1
    reason = "skip"
    for model, limiter_key in _TRANSLATION_STAGES:
        out, reason = _translate_chunk_with(chunk, prompt, model, limiter_key, max_attempts)
        if out is not None:
            return out, "ok"
        if reason not in _TR_STAGE_ADVANCE:
            return None, reason
    return None, reason


def _translate_chunk_with(chunk: List[Dict], prompt: str, model: str, limiter_key: str,
                          max_attempts: int) -> Tuple[Optional[Dict[str, Tuple[str, str]]], str]:
    for attempt in range(1, max_attempts + 1):
        try:
            if not rate_limit_manager.check_and_wait(limiter_key):
                return None, "skip"
            response = gemini_client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=3072,
                    temperature=0.3,
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )],
                    automatic_function_calling=_NO_AFC,
                )
            )
            tokens = 0
            usage = getattr(response, "usage_metadata", None)
            if usage is not None:
                tokens = getattr(usage, "total_token_count", 0) or 0
            rate_limit_manager.record_call(limiter_key, tokens_used=tokens)

            text = (response.text or "").strip()
            text = re.sub(r"```(?:json)?\s*\n?", "", text).strip()
            try:
                arr = json.loads(text)
            except json.JSONDecodeError:
                m = re.search(r'\[[\s\S]*\]', text)
                if not m:
                    logger.warning(f"일괄 번역 파싱 실패 (JSON 배열 없음, 시도 {attempt})")
                    return None, "parse"
                arr = json.loads(m.group())

            if not isinstance(arr, list):
                return None, "parse"
            by_n = {int(o.get('n', 0)): o for o in arr if isinstance(o, dict)}
            out: Dict[str, Tuple[str, str]] = {}
            for n, it in enumerate(chunk, 1):
                o = by_n.get(n, {})
                title_ko = (o.get('title_ko') or '').strip() or it['title']
                desc_ko = (o.get('desc_ko') or '').strip() or (it['description'] or '')[:200]
                out[it['id']] = (title_ko, desc_ko)
            return out, "ok"

        except json.JSONDecodeError as e:
            logger.warning(f"일괄 번역 파싱 실패: {e}")
            return None, "parse"
        except Exception as e:
            msg = str(e)
            kind = _gemini_error_kind(msg)
            if kind == "rpd":
                rate_limit_manager.mark_rpd_exhausted(limiter_key)
                logger.warning(f"일괄 번역 일일 한도(RPD) 소진: {model}")
                return None, "skip"
            if kind in ("rate", "transient") and attempt < max_attempts:
                wait = _gemini_backoff(kind, attempt, msg)
                logger.warning(f"일괄 번역 {kind} 오류({model} {attempt}/{max_attempts}): {e} → {wait:.0f}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"일괄 번역 청크 실패({model} {kind}): {e}")
            return None, kind
    return None, "api"


def _recheck_soon() -> str:
    return (datetime.datetime.now(KST) - datetime.timedelta(days=6)).isoformat()


def check_for_official_rules(db: Store, notifier: SlackNotifier,
                             deadline_ts: Optional[float] = None) -> None:
    try:
        logger.info("=== 공식 룰 재발견 체크 시작 ===")

        rule_manager = RuleManager()
        if not rule_manager_index_ok():
            logger.warning("탐지 룰 인덱스 미적재 — 재확인을 건너뛴다 "
                           "(쿨다운을 소모하면 7일간 다시 못 본다)")
            return

        max_recheck = config.PERFORMANCE["max_rule_recheck"]
        # 색인에서 룰이 늘어난 CVE 를 먼저 본다 — 이미 룰이 있던 CVE 는 아래에서 알림 없이 스냅샷만 바꾼다.
        grown, built_at = rule_manager_grown()
        candidates, known = rule_refresh.plan(db, grown, built_at, max_recheck)
        known = known[:config.PERFORMANCE["max_rule_refresh"]]

        if not candidates and not known:
            logger.info("재확인 대상 없음")
            return
        logger.info(f"재확인 대상: {len(candidates)}건 · 룰이 늘어난 CVE(이미 룰 있음) {len(known)}건")

        found_count = 0

        for record in candidates:
            if deadline_ts is not None and time.time() > deadline_ts:
                logger.warning("⏰ 시간 예산 도달 — 공식 룰 재확인 중단 "
                               "(쿨다운을 안 쓴 대상은 다음 실행이 그대로 이어받는다)")
                break
            cve_id = record['id']

            try:
                rules, complete = rule_manager.search_public_only(cve_id)
                now_iso = datetime.datetime.now(KST).isoformat()

                if not complete:
                    db.upsert_cve({
                        "id": cve_id,
                        "last_rule_check_at": _recheck_soon(),
                        "updated_at": now_iso
                    })
                    continue

                has_official = bool(
                    rules.get('network')
                    or any(rules.get(k) for k in ('sigma', 'yara', 'nuclei', 'splunk'))
                )

                if has_official:
                    found_count += 1
                    logger.info(f"✅ {cve_id}: 공식 룰 발견!")

                    full = db.get_cve(cve_id) or {}
                    title_ko = (full.get('last_alert_state') or {}).get('title_ko') or cve_id
                    notifier.send_official_rule_update(
                        cve_id=cve_id,
                        title=title_ko,
                        rules_info=rules,
                        dashboard_url=_cve_url(cve_id),
                    )

                    db.upsert_cve({
                        "id": cve_id,
                        "has_official_rules": True,
                        "rules_snapshot": rules,
                        "last_rule_check_at": now_iso,
                        "updated_at": now_iso
                    })
                else:
                    db.upsert_cve({
                        "id": cve_id,
                        "last_rule_check_at": now_iso,
                        "updated_at": now_iso
                    })

            except Exception as e:
                logger.error(f"{cve_id} 공식 룰 체크 실패: {e}")
                try:
                    db.upsert_cve({
                        "id": cve_id,
                        "last_rule_check_at": _recheck_soon(),
                        "updated_at": datetime.datetime.now(KST).isoformat()
                    })
                except Exception as e:
                    logger.warning(f"{cve_id} 룰 재확인 쿨다운 기록 실패: {e}")
                continue

        refreshed = rule_refresh.refresh_known(
            db, rule_manager.search_public_only, known,
            now=lambda: datetime.datetime.now(KST).isoformat(), soon=_recheck_soon,
            deadline_ts=deadline_ts)
        logger.info(f"=== 공식 룰 재발견 체크 완료 (발견: {found_count}건 · 스냅샷 갱신: {refreshed}건) ===")

    except Exception as e:
        logger.error(f"공식 룰 체크 프로세스 실패: {e}")


def backfill_reports(db: Store, deadline_ts: float, limit: int = 0) -> int:
    if all(rate_limit_manager.is_rpd_exhausted(key)
           for _model, key in config.ANALYSIS_MODELS):
        logger.warning("분석 2단 모두 소진 → 리포트 보강 생략 (다음 실행 재시도)")
        return 0

    limit = limit or config.PERFORMANCE["analysis_per_run"]
    rows = db.get_missing_report_candidates(limit=limit)
    if not rows:
        logger.info("리포트 보강: 대상 없음")
        return 0

    left = db.count_missing_reports()
    backlog = " · ".join(f"{t} {n:,}" for t, n in sorted(left.items())) or "0"
    logger.info(f"📝 리포트 보강 대상 {len(rows)}건 (분석 없는 고위험 {backlog}건 남음)")
    made = 0
    for row in rows:
        if time.time() > deadline_ts:
            logger.warning("⏰ 시간 예산 도달 — 리포트 보강 중단 (다음 실행 이어받음)")
            break
        state = row.get('last_alert_state') or {}
        state.setdefault('id', row['id'])
        state.setdefault('cvss', row.get('cvss_score') or 0.0)
        state.setdefault('epss', row.get('epss_score') or 0.0)
        state.setdefault('is_kev', bool(row.get('is_kev')))
        state.setdefault('references', [])
        state.setdefault('description', 'N/A')
        state.setdefault('title', row['id'])
        state.setdefault('title_ko', state.get('title') or row['id'])
        reason = " · ".join(
            risk.TRIGGERS[k].label for k in (state.get('fired_triggers') or [])
            if k in risk.TRIGGERS) or "고위험 판정"
        try:
            analysis, rules_info = make_analysis(state, reason)
        except Exception as e:
            logger.error(f"{row['id']} 분석 실패: {e}")
            continue
        if not analysis:
            continue
        state['analysis'] = analysis
        payload = {"id": row['id'], "last_alert_state": state,
                   "updated_at": row.get('updated_at')
                   or datetime.datetime.now(KST).isoformat()}
        if rules_info:
            payload["has_official_rules"] = rules_info.get('has_official', False)
            payload["rules_snapshot"] = rules_info.get('rules')
            payload["last_rule_check_at"] = datetime.datetime.now(KST).isoformat()
        if db.upsert_cve(payload):
            made += 1
    logger.info(f"📝 리포트 보강 완료: {made}/{len(rows)}건")
    if made:
        db.request_full_export()
    return made


def sweep_heavy_signals(collector: Collector, db: Store, notifier: SlackNotifier,
                        deadline_ts: float) -> List[pipeline.Outcome]:
    outcomes: List[pipeline.Outcome] = []
    cap = config.PERFORMANCE["snapshot_cap"]
    epss_index = enrichment_sources.load_epss_above(risk.EPSS_P_HIGH)

    for diff in signal_snapshot.sweep(db, cap=cap,
                                      only=[k for k, s in signal_snapshot.SOURCES.items()
                                            if not s.fast]):
        if not diff.added:
            continue
        if time.time() > deadline_ts:
            logger.warning(f"⏰ [{diff.source.label}] 시간 예산 도달 — 나머지는 다음 실행")
            break
        targets = {t: signal_snapshot.cve_of(t) for t in diff.added}
        records, absent = feed.fetch_records(
            list(targets.values()), workers=config.PERFORMANCE["max_workers"] * 2)
        processed: List[str] = [t for t, c in targets.items() if c in absent]
        for token, cve_id in targets.items():
            if time.time() > deadline_ts:
                logger.warning(f"⏰ [{diff.source.label}] 시간 예산 도달 — 나머지는 다음 실행")
                break
            record = records.get(cve_id)
            if record is None:
                continue
            try:
                st = pipeline.build_state(cve_id, record, collector, epss_index)
            except Exception as e:
                logger.warning(f"{cve_id} 상태 구성 실패: {e}")
                continue
            if st is None:
                processed.append(token)
                continue
            out = pipeline.process(st, db, notifier,
                                   reason_prefix=f"[{diff.source.label}] ",
                                   make_report=make_analysis)
            outcomes.append(out)
            if not out.needs_retry:
                processed.append(token)
        signal_snapshot.commit(db, diff, processed)
    return outcomes


def _main() -> None:
    started = time.time()
    logger.info("=" * 60)
    logger.info("Argus bulk-lane 시작")
    logger.info("=" * 60)

    deadline = started + config.PERFORMANCE["bulk_deadline_minutes"] * 60
    collector = Collector()
    db = create_store()
    notifier = SlackNotifier()
    rate_limit_manager.import_rpd_state(pstate.read_rpd_state())

    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    collector.ai_ledger = ai_provenance.load_anthropic_ledger()
    package_index.get()

    outcomes = sweep_heavy_signals(collector, db, notifier, deadline)
    if outcomes:
        logger.info(pipeline.summarize(outcomes))

    backfill_reports(db, deadline)

    translate_tracked(db, deadline)

    pstate.write_rpd_state(rate_limit_manager.export_rpd_state())

    tracked = sum(1 for o in outcomes if o.status == "tracked")
    notifier.send_batch_summary(dashboard_url=_dashboard_url(), tracked=tracked)

    if time.time() < deadline:
        check_for_official_rules(db, notifier, deadline)

    logger.info("=" * 60)
    logger.info(f"bulk-lane 완료 · {time.time() - started:.1f}초")
    logger.info("=" * 60)
    rate_limit_manager.print_summary()


def _notify_pipeline_failure(error: Exception) -> None:
    try:
        SlackNotifier().send_pipeline_warning(
            "🔴 Argus bulk-lane 실패", f"```{type(error).__name__}: {error}```")
    except Exception:
        pass


def main() -> None:
    try:
        _main()
    except Exception as e:
        logger.error(f"bulk-lane 최상위 실패: {e}", exc_info=True)
        _notify_pipeline_failure(e)


if __name__ == "__main__":
    main()
