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
import translation
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
from rule_manager import built_at as rule_manager_built_at
from rule_manager import index_ok as rule_manager_index_ok
from rule_manager import indexed_ids as rule_manager_ids
from rule_manager import missing as rule_manager_missing

KST = pytz.timezone('Asia/Seoul')

try:
    gemini_client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
        http_options=types.HttpOptions(timeout=120_000),
    )
except Exception:
    gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))


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

    run = {"sent": 0, "failed": 0, "unusable": 0, "seen": set(),
           "done": {"우선": 0, "차례": 0, "제목": 0}}
    scanned_total = 0
    max_windows = (total // pool + 2) if total else 25
    try:
        # 1) 먼저 — 알림 등급(T0 · T1)이거나 최근 공개된 CVE 중 한국어 제목이 없는 것.
        #    CVE 번호 순서로만 돌면 새 알림(번호가 큰 행)이 한 바퀴를 기다린다.
        days = config.PERFORMANCE["translation_priority_days"]
        since = (datetime.datetime.now(datetime.timezone.utc).date()
                 - datetime.timedelta(days=days)).isoformat()
        rows = db.get_translation_priority_candidates(limit=budget, since=since,
                                                      rule=translation.TITLE_RULE)
        items = [translation.make_item(r['id'], r['last_alert_state'] or {})
                 for r in rows if _wanted(r, run)]
        if items:
            logger.info(f"🈯 우선 번역 {len(items)}건 (알림 등급 · 최근 {days}일 공개 · 한국어 제목 없음)")
            _translate_items(db, items, stop_ts, run, "우선")

        # 2) 그다음 — 지금까지처럼 CVE 번호 순서로 돈다(제목 · 설명 중 하나라도 한국어가 아닌 행).
        while (run["sent"] < budget and time.time() < stop_ts and max_windows > 0
               and not _translation_exhausted()):
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
                if not _wanted(row, run):
                    continue
                items.append(translation.make_item(row['id'], row.get('last_alert_state') or {}))
                if len(items) >= budget - run["sent"]:
                    break

            next_offset = offset + scanned
            wrapped = bool(total and next_offset >= total) or len(candidates) < pool
            pstate.write_backfill_offset(0 if wrapped else next_offset)
            scanned_total += scanned

            if items:
                logger.info(f"🈯 영문 {len(items)}건 처리 "
                            f"(스캔 {offset:,}~{offset + scanned:,}/{total:,}행)")
                _translate_items(db, items, stop_ts, run, "차례")

            if wrapped:
                logger.info("번역: 전체를 한 바퀴 돌았다 — 다음 회차는 처음부터")
                break

        # 3) 마지막 — '제품 이름 + 취약점' 제목을 다시 만든다. 남은 한도 안에서 회차마다 조금씩.
        _regenerate_generic_titles(db, budget, stop_ts, run)
    except Exception as e:
        logger.warning(f"번역 중단(오류): {e}")

    if _translation_exhausted():
        logger.warning("번역 중단 — 일일 한도(RPD/TPD) 소진. 남은 대상은 한도가 "
                       "풀린 뒤 다음 회차가 이어받는다 (창 위치는 저장돼 있다)")
    done = sum(run["done"].values())
    if done:
        db.request_full_export()
    by = run["done"]
    logger.info(f"🈯 번역 완료: {done:,}건 한글화 (우선 {by['우선']:,} · 차례 {by['차례']:,} · "
                f"제목 다시 만들기 {by['제목']:,}) · 답 없음 {run['failed']:,}건(다음 회차가 다시 보낸다) · "
                f"쓸 수 없는 답 {run['unusable']:,}건 · {scanned_total:,}행 스캔 · "
                f"{'다음 export는 전량' if done else '변경 없음'}")
    return done


def _wanted(row: Dict, run: Dict) -> bool:
    state = row.get('last_alert_state') or {}
    return (row['id'] not in run["seen"] and translation.wants(state)
            and not translation.tried(state))


def _translate_items(db: Store, items: List[Dict], stop_ts: float, run: Dict, label: str) -> None:
    run["seen"].update(it['id'] for it in items)
    run["sent"] += len(items)
    answers = generate_korean_summaries_batch(items, deadline_ts=stop_ts)
    patches = []
    for it in items:
        answer = answers.get(it['id'])
        if answer is None:
            run["failed"] += 1  # 답이 없었다(오류 · 한도 · 시간 초과) — 표시하지 않는다. 다음 회차가 다시 보낸다
            continue
        patch = translation.review(it, answer)
        patches.append({"id": it['id'], "patch": patch})
        if "title_ko" in patch or "desc_ko" in patch:
            run["done"][label] += 1
        if "ko_tried" in patch:
            run["unusable"] += 1
    if patches:
        db.patch_states(patches, "번역")


def _regenerate_generic_titles(db: Store, budget: int, stop_ts: float, run: Dict) -> None:
    cap = min(config.PERFORMANCE["translation_regen_per_run"], budget - run["sent"])
    if cap <= 0 or time.time() >= stop_ts or _translation_exhausted():
        return
    # 끝이 '취약점'인 제목을 cap 의 5배까지 본다 — 유형이 있는 제목은 '지금 규칙으로 봄'(ko_rule)으로 적어
    # 다음 회차부터 꺼내지 않는다. 그래서 한 번 다 보고 나면 이 조회는 새로 쌓인 것만 돌려준다.
    rows = db.get_title_regen_candidates(limit=cap * 5, rule=translation.TITLE_RULE)
    items, checked = [], []
    for row in rows:
        state = row.get('last_alert_state') or {}
        if row['id'] in run["seen"]:
            continue
        if not translation.is_generic_title(state.get('title_ko')):
            checked.append({"id": row['id'], "patch": {"ko_rule": translation.TITLE_RULE}})
        elif len(items) < cap:
            items.append(translation.make_item(row['id'], state))
    if checked:
        db.patch_states(checked, "제목 확인")
    if items:
        logger.info(f"🈯 제목 다시 만들기 {len(items)}건 ('제품 이름 + 취약점' · 회차당 최대 "
                    f"{config.PERFORMANCE['translation_regen_per_run']}건)")
        _translate_items(db, items, stop_ts, run, "제목")


def _translation_exhausted() -> bool:
    return all(rate_limit_manager.is_rpd_exhausted(key)
               for _model, key in _TRANSLATION_STAGES)


_NO_AFC = types.AutomaticFunctionCallingConfig(disable=True)

_TRANSLATION_STAGES = config.TRANSLATION_MODELS

_TR_STAGE_ADVANCE = ("skip", "rate", "transient")


def generate_korean_summary(item: Dict, retry_on_transient: bool = False) -> Optional[Tuple[str, str]]:
    """한 건 번역 — 일괄 번역 응답이 깨졌을 때만 쓴다. 답이 없으면 None(원문으로 채우지 않는다)."""
    prompt = translation.single_prompt(item)
    max_attempts = 3 if retry_on_transient else 1

    reason = "skip"
    for model, limiter_key in _TRANSLATION_STAGES:
        out, reason = _translate_one(prompt, model, limiter_key, max_attempts)
        if out is not None:
            _tr_bump("ok")
            return out
        if reason not in _TR_STAGE_ADVANCE:
            break
    _tr_bump(_TR_REASON_KEY.get(reason, "en_other"))
    return None


_ANSWER_LINE = re.compile(r"^\W*(제목|내용)\W*?[:：]\s*(.*)$")


def _translate_one(prompt: str, model: str, limiter_key: str,
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
            found = {}
            for line in text.split('\n'):
                m = _ANSWER_LINE.match(line.strip())
                if m and m.group(1) not in found:
                    found[m.group(1)] = m.group(2).strip().strip('*').strip()
            if not (found.get("제목") or found.get("내용")):
                logger.warning(f"번역 응답 형식 파손({model}) — '제목:' · '내용:' 줄이 없다")
                return None, "parse"
            return (found.get("제목", ""), found.get("내용", "")), "ok"

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
              ("en_deadline", "시간초과"), ("en_missing", "답에서 빠짐"), ("en_other", "기타")]
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
    missed = sum(snap.get(k, 0) for k, _ in _TR_LABELS)
    if not (ok or missed):
        return
    breakdown = " · ".join(f"{label} {snap.get(key, 0)}" for key, label in _TR_LABELS)
    rpd = " · ".join(
        f"{model} {u:,}/{l:,}"
        for model, u, l in ((m,) + rate_limit_manager.rpd_status(k) for m, k in _TRANSLATION_STAGES)
    )
    logger.info(f"🈯 번역 요약(누적): 답 받음 {ok}건 · 답 없음 {missed}건 "
                f"({breakdown}) — 답 없는 항목은 다음 회차가 다시 보낸다 · RPD {rpd}")


def generate_korean_summaries_batch(items: List[Dict],
                                    deadline_ts: Optional[float] = None) -> Dict[str, Tuple[str, str]]:
    """모델이 답한 항목만 {id: (제목, 설명)} 으로 돌려준다 — 오류 · 한도 · 시간 초과 · 답에서 빠진 항목은 없다.

    실패를 원문으로 채워 돌려주면 부르는 쪽은 '모델이 영어로 답했다'와 구별하지 못한다. 2026-11 까지 그래서
    실패한 행에 '시도함'이 붙어 다시는 번역되지 않았다.
    """
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


    def _do_chunk(chunk: List[Dict]) -> Dict[str, Tuple[str, str]]:
        out: Dict[str, Tuple[str, str]] = {}
        if deadline_ts is not None and time.time() > deadline_ts:
            with lock:
                if not state["deadline_warned"]:
                    logger.warning(f"⏰ 번역 시간 예산 도달 — 남은 ~{total_chunks - state['done']}청크는 "
                                   f"다음 회차가 보낸다")
                    state["deadline_warned"] = True
            _tr_bump("en_deadline", len(chunk))
            return out
        try:
            parsed, reason = _translate_chunk(chunk, retry_on_transient=True)
            if parsed is not None:
                out.update(parsed)
                _tr_bump("ok", len(parsed))
                _tr_bump("en_missing", len(chunk) - len(parsed))
            elif reason == "parse":
                with lock:
                    state["fell_back"] += len(chunk)
                for it in chunk:
                    answer = generate_korean_summary(it, retry_on_transient=True)
                    if answer is not None:
                        out[it['id']] = answer
            else:
                _tr_bump(_TR_REASON_KEY.get(reason, "en_other"), len(chunk))
        except Exception as e:
            logger.warning(f"번역 청크 실패 — 다음 회차가 다시 보낸다: {e}")
            _tr_bump("en_other", len(chunk) - len(out))
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
    prompt = translation.batch_prompt(chunk)
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
            by_n: Dict[int, Dict] = {}
            for o in arr:
                if isinstance(o, dict):
                    try:
                        by_n.setdefault(int(o.get('n', 0)), o)
                    except (TypeError, ValueError):
                        continue
            if not any(1 <= n <= len(chunk) for n in by_n) and len(arr) == len(chunk):
                # 번호(n)를 빼먹고 순서대로만 답했다 — 순서로 맞춘다
                by_n = {n: o for n, o in enumerate(arr, 1) if isinstance(o, dict)}
            out: Dict[str, Tuple[str, str]] = {}
            for n, it in enumerate(chunk, 1):
                o = by_n.get(n) or {}
                title_ko = str(o.get('title_ko') or '').strip()
                desc_ko = str(o.get('desc_ko') or '').strip()
                if title_ko or desc_ko:
                    out[it['id']] = (title_ko, desc_ko)  # 답에서 빠진 항목은 넣지 않는다 — 다음 회차가 다시 보낸다
            if not out:
                logger.warning(f"일괄 번역 파싱 실패 (쓸 수 있는 항목 없음, 시도 {attempt})")
                return None, "parse"
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
        # 화면의 룰 스냅샷에 지금 색인의 룰이 빠진 CVE 를 먼저 본다 — 이미 룰이 있던 CVE 는 아래에서 알림 없이 스냅샷만 바꾼다.
        candidates, known = rule_refresh.plan(db, rule_manager_ids(), rule_manager_built_at(),
                                              max_recheck, rule_manager_missing)
        known = known[:config.PERFORMANCE["max_rule_refresh"]]

        if not candidates and not known:
            logger.info("재확인 대상 없음")
            return
        logger.info(f"재확인 대상: {len(candidates)}건 · 스냅샷만 바꿀 CVE(이미 탐지 룰 있음) {len(known)}건")

        found_count = 0
        template_only = 0

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

                # 알림은 탐지 룰(Sigma · Snort · Suricata · Splunk · YARA)이 처음 생겼을 때만. nuclei 점검 템플릿만 찾으면
                # 화면에 싣도록 스냅샷만 남긴다 — 템플릿은 등급 판정의 T1 근거라 새로 생기면 즉시 알림이 따로 나간다.
                kind = rule_refresh.found_kind(rules)

                if kind == "detection":
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
                elif kind == "check":
                    template_only += 1
                    logger.info(f"{cve_id}: nuclei 점검 템플릿만 — 탐지 룰이 아니라 알림 없이 스냅샷만 남긴다")
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
        logger.info(f"=== 공식 룰 재발견 체크 완료 (탐지 룰 발견: {found_count}건 · nuclei 템플릿만: {template_only}건 · "
                    f"스냅샷 갱신: {refreshed}건) ===")

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
        # 분석은 수십 초가 걸린다 — 그 사이 fast-lane 이 바꾼 상태를 덮지 않게 analysis 키만 쓴다.
        payload = {"id": row['id'], "patch": {"analysis": analysis}}
        if rules_info:
            payload["has_official_rules"] = rules_info.get('has_official', False)
            payload["rules_snapshot"] = rules_info.get('rules')
            payload["last_rule_check_at"] = datetime.datetime.now(KST).isoformat()
        if db.patch_states([payload], "리포트"):
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

    tracked = sum(1 for o in outcomes if o.status == "tracked" and o.fresh)
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
        # 예외를 삼키면 실행이 초록으로 끝나 실패가 Actions 목록에 보이지 않는다.
        # export · 배포 단계는 if: always() 라 이 단계가 실패해도 이어서 돈다.
        raise


if __name__ == "__main__":
    main()
