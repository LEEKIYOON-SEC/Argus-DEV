(function (root, factory) {
  'use strict';
  const node = typeof module !== 'undefined' && module.exports;
  const api = factory(node ? require('./lifecycle.js') : root.ArgusLifecycle);
  root.ArgusContext = api;
  if (node) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis, function (LC) {
  'use strict';

  /*
   * 파생 계층 — 원본 필드(cves.json · cve-products · cve-packages · lifecycle)를 CVE 중심 맥락으로 묶는다.
   * 규칙은 모두 결정적이다. 점수를 합산하지 않고, AI 분석(analysis)은 읽지도 않는다.
   * 모든 판정은 yes / no / unknown 셋 중 하나다 — 근거가 없으면 no 가 아니라 unknown.
   * 브라우저와 CI(src/build_context.js)가 이 파일 하나를 함께 쓴다.
   */

  // src/risk.py 의 epss_high 트리거와 같은 기준(백분위 95, 백분위가 없으면 확률 9.3%).
  const EPSS_P_HIGH = 0.95;
  const EPSS_SCORE_HIGH = 0.093;
  const CVSS_CRITICAL = 9.0;

  const URL = {
    cveRecord: id => `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`,
    nvd: id => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
    epss: id => `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}`,
    osv: id => `https://osv.dev/list?q=${encodeURIComponent(id)}`,
    kev: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    vulncheck: 'https://vulncheck.com/kev',
    metasploit: 'https://github.com/rapid7/metasploit-framework',
    poc: 'https://github.com/nomi-sec/PoC-in-GitHub',
    exploitdb: 'https://www.exploit-db.com/',
    endoflife: 'https://endoflife.date/',
  };

  // 룰 엔진 — detect: 공격·악성 행위 탐지 룰, check: 대상에 요청을 보내 취약 여부를 확인하는 점검 템플릿.
  const ENGINES = {
    sigma: { label: 'Sigma', kind: 'detect', source: 'SigmaHQ' },
    splunk: { label: 'Splunk ESCU', kind: 'detect', source: 'Splunk security_content' },
    yara: { label: 'YARA', kind: 'detect', source: 'YARA Forge' },
    snort2: { label: 'Snort 2', kind: 'detect', source: 'ET Open · Snort Community' },
    snort3: { label: 'Snort 3', kind: 'detect', source: 'ET Open · Snort Community' },
    suricata5: { label: 'Suricata 5', kind: 'detect', source: 'ET Open' },
    suricata7: { label: 'Suricata 7', kind: 'detect', source: 'ET Open' },
    nuclei: { label: 'nuclei', kind: 'check', source: 'nuclei-templates' },
  };
  const ENGINE_ORDER = ['sigma', 'suricata7', 'suricata5', 'snort3', 'snort2', 'splunk', 'yara', 'nuclei'];
  const NETWORK = new Set(['snort2', 'snort3', 'suricata5', 'suricata7']);
  const engineInfo = e => ENGINES[e] || { label: e, kind: 'detect', source: e };
  const isCheck = e => engineInfo(e).kind === 'check';
  // 탐지 룰 엔진 계열 — 검색어 has:<key> · 목록 태그 · 필터 칩이 이 순서를 쓴다. 판(Snort 2/3 · Suricata 5/7)은 나누지 않는다
  // (실측 2026-11-23: Suricata 5 · 7 은 1,203건이 모두 같은 CVE). nuclei 는 점검 템플릿이라 넣지 않는다.
  const RULE_FAMILIES = [
    { key: 'snort', label: 'Snort', engines: ['snort2', 'snort3'] },
    { key: 'suricata', label: 'Suricata', engines: ['suricata5', 'suricata7'] },
    { key: 'sigma', label: 'Sigma', engines: ['sigma'] },
    { key: 'yara', label: 'YARA', engines: ['yara'] },
    { key: 'splunk', label: 'Splunk', engines: ['splunk'] },
  ];

  /* ---------- 신호 정의 (코드 · 질문 · 정의 · 검색어) ---------- */

  const SIGNALS = [
    { code: 'EXPLOITATION_CONFIRMED', group: 'exploitation', short: '악용 근거', key: 'kev',
      question: '실제 악용 근거가 있는가',
      def: 'CISA KEV 또는 VulnCheck KEV에 등재됐거나 CISA SSVC 판정이 Exploitation: active인 경우. 세 출처 모두 실제 악용 보고를 기준으로 등재합니다' },
    { code: 'CISA_KEV', group: 'exploitation', short: 'CISA KEV', key: 'cisa-kev',
      question: 'CISA KEV에 등재됐는가', def: 'CISA Known Exploited Vulnerabilities 카탈로그 등재 여부' },
    { code: 'PUBLIC_EXPLOIT', group: 'weaponization', short: '공개 익스플로잇', key: 'exploit',
      question: '공개된 익스플로잇이 있는가',
      def: 'Exploit-DB 항목, Metasploit 모듈, 공개 PoC 저장소 중 하나 이상. 공개돼 있다는 뜻이며 실제 공격이 있었다는 뜻은 아닙니다' },
    { code: 'AUTOMATABLE', group: 'automation', short: '자동화 가능', key: 'auto',
      question: '자동화된 대량 공격이 가능한가', def: 'CISA SSVC 판정이 Automatable: yes인 경우. no는 출처가 명시한 판정이고, 판정이 없으면 미확인입니다' },
    { code: 'RANSOMWARE', group: 'ransomware', short: '랜섬웨어', key: 'ransom',
      question: '랜섬웨어 캠페인에 쓰였는가',
      def: 'CISA KEV에 랜섬웨어 캠페인 사용(Known)으로 적힌 경우. KEV의 Unknown이나 미등재는 \'없음\'이 아니라 미확인입니다' },
    { code: 'EOL_AFFECTED', group: 'lifecycle', short: 'EOL 포함', key: 'eol',
      question: '영향받는 버전 중 지원이 끝난(EOL) 것이 있는가',
      def: '영향받는 제품 버전 가운데 하나 이상이 오늘 기준으로 지원 종료(EOL, endoflife.date 기준)인 경우. 취약점의 심각도가 아니라 제품의 지원 상태입니다' },
    { code: 'PATCH_AVAILABLE', group: 'remediation', short: '수정 버전', key: 'patch',
      question: '수정 버전이 있는가',
      def: 'OSV에 이 CVE의 수정 버전이 하나 이상 있는 경우. OSV 기록은 있는데 수정 버전이 없으면 없음, OSV 기록이 없으면 미확인입니다' },
    { code: 'PUBLIC_DETECTION', group: 'detection', short: '탐지 룰', key: 'detection',
      question: '공개된 탐지 룰이 있는가',
      def: 'Sigma · Snort · Suricata · Splunk · YARA 룰 중 하나 이상. Argus가 색인하는 공개 저장소 기준입니다. nuclei 점검 템플릿은 대상에 요청을 보내 취약한지 확인하는 템플릿이라 넣지 않습니다' },
    { code: 'HIGH_EPSS', group: 'scores', short: 'EPSS 상위 5%', key: 'high-epss',
      question: '악용 확률 예측이 높은가',
      def: 'EPSS 백분위 95 이상(백분위가 없으면 확률 9.3% 이상, 알림 판정과 같은 기준). 예측값이며 악용이 확인됐다는 뜻은 아닙니다' },
    { code: 'CRITICAL_CVSS', group: 'scores', short: 'CVSS 9+', key: 'critical',
      question: '기본 심각도가 Critical인가', def: 'CVSS 기본 점수 9.0 이상. 점수가 없으면 미확인입니다' },
  ];
  const SIGNAL = Object.fromEntries(SIGNALS.map(s => [s.code, s]));
  const SIGNAL_BY_KEY = Object.fromEntries(SIGNALS.map(s => [s.key, s.code]));
  // 같은 신호의 다른 이름. 예전 값(patched · rules)은 2026-11 필터 정리에서 지웠다(INVARIANTS §6).
  Object.assign(SIGNAL_BY_KEY, { exploited: 'EXPLOITATION_CONFIRMED', automatable: 'AUTOMATABLE' });

  // 신호 조합 — 두 신호가 모두 yes 일 때만 만든다. '!' 는 명시적 no (unknown 은 해당 없음).
  const CORRELATIONS = [
    { code: 'KEV_EOL', parts: ['CISA_KEV', 'EOL_AFFECTED'], short: 'KEV × EOL',
      label: 'CISA KEV에 있고 영향 버전 중 EOL이 있음', query: 'has:cisa-kev lifecycle:eol' },
    { code: 'KEV_PUBLIC_EXPLOIT', parts: ['CISA_KEV', 'PUBLIC_EXPLOIT'], short: 'KEV × 공개 익스플로잇',
      label: 'CISA KEV에 있고 공개 익스플로잇도 있음', query: 'has:cisa-kev has:exploit' },
    { code: 'KEV_AUTOMATABLE', parts: ['CISA_KEV', 'AUTOMATABLE'], short: 'KEV × 자동화',
      label: 'CISA KEV에 있고 SSVC 판정상 자동화 가능', query: 'has:cisa-kev has:auto' },
    { code: 'KEV_RANSOMWARE', parts: ['CISA_KEV', 'RANSOMWARE'], short: 'KEV × 랜섬웨어',
      label: 'CISA KEV에 랜섬웨어 캠페인 사용으로 적힘', query: 'has:cisa-kev has:ransom' },
    { code: 'HIGH_EPSS_KEV', parts: ['HIGH_EPSS', 'CISA_KEV'], short: 'EPSS 상위 5% × KEV',
      label: 'EPSS 상위 5%이면서 CISA KEV에 있음', query: 'has:high-epss has:cisa-kev' },
    { code: 'CRITICAL_PUBLIC_EXPLOIT', parts: ['CRITICAL_CVSS', 'PUBLIC_EXPLOIT'], short: 'CVSS 9+ × 공개 익스플로잇',
      label: 'CVSS 9.0 이상이고 공개 익스플로잇도 있음', query: 'cvss:>=9 has:exploit' },
    { code: 'CRITICAL_EOL', parts: ['CRITICAL_CVSS', 'EOL_AFFECTED'], short: 'CVSS 9+ × EOL',
      label: 'CVSS 9.0 이상이고 영향 버전 중 EOL이 있음', query: 'cvss:>=9 lifecycle:eol' },
    { code: 'PATCH_EXPLOITED', parts: ['PATCH_AVAILABLE', 'EXPLOITATION_CONFIRMED'], short: '수정 버전 × 악용 근거',
      label: '악용 근거가 있고 수정 버전도 나와 있음 (바로 업데이트할 대상)', query: 'has:patch has:kev' },
    { code: 'EXPLOIT_NO_FIX', parts: ['PUBLIC_EXPLOIT', '!PATCH_AVAILABLE'], short: '공개 익스플로잇 × 수정 기록 없음',
      label: '공개 익스플로잇이 있는데 OSV에 수정 버전 기록이 없음', query: 'has:exploit no:patch' },
    { code: 'EOL_NO_FIX', parts: ['EOL_AFFECTED', '!PATCH_AVAILABLE'], short: 'EOL × 수정 기록 없음',
      label: '영향 버전 중 EOL이 있고 OSV에 수정 버전 기록이 없음', query: 'lifecycle:eol no:patch' },
  ];
  const CORRELATION = Object.fromEntries(CORRELATIONS.map(c => [c.code, c]));

  const REASON = {
    cvss_unscored: 'CVSS 점수 없음',
    epss_unscored: 'EPSS 미채점 (새 CVE는 아직 채점 전일 수 있음)',
    ssvc_missing: 'CISA SSVC 판정 없음',
    kev_unknown: 'KEV에 랜섬웨어 사용이 Unknown으로 적혀 있음',
    not_in_kev: 'KEV에 없어 랜섬웨어 사용 여부를 알 수 없음',
    no_osv_record: 'OSV 기록 없음 (OSV가 다루지 않는 제품이거나 아직 수집 전)',
    no_affected: '영향 제품 정보 없음',
    untracked: '수명주기를 추적하지 않는 제품이 있음 (endoflife.date에 연결 안 됨)',
    unresolved: '제품은 찾았지만 영향 버전이 어느 릴리스인지 정하지 못함',
    status_unknown: '제조사 일정에 보안·확장 지원 단계가 없어 상태를 정하지 못함',
    lifecycle_unloaded: '수명주기 데이터를 불러오지 못함',
    rules_unlisted: '공개 룰이 있다고만 기록되고 어떤 룰인지 남아 있지 않음 (nuclei 점검 템플릿일 수 있음)',
  };

  /* ---------- 기본 판정 (목록·검색·통계가 쓰는 빠른 경로) ---------- */

  const t = b => (b ? 'yes' : 'no');

  function scoreFacts(cve) {
    const cvss = Number(cve.cvss) || 0;
    const epss = Number(cve.epss) || 0;
    const pct = Number(cve.epss_percentile) || 0;
    return {
      cvss: cvss > 0 ? cvss : null,
      epss: epss > 0 || pct > 0 ? epss : null,
      percentile: pct > 0 ? pct : null,
    };
  }

  function epssHigh(cve) {
    const f = scoreFacts(cve);
    if (f.epss === null) return 'unknown';
    return t(f.percentile !== null ? f.percentile >= EPSS_P_HIGH : f.epss >= EPSS_SCORE_HIGH);
  }

  function hasFix(pkgMap) {
    return Object.values(pkgMap || {}).some(ecoMap =>
      Object.values(ecoMap || {}).some(fixes => (fixes || []).some(Boolean)));
  }

  function patchState(pkgMap) {
    if (!pkgMap || !Object.keys(pkgMap).length) return 'unknown';
    return t(hasFix(pkgMap));
  }

  // 룰 목록에 싣는 엔진 전부 — 탐지 룰과 점검 템플릿(nuclei)을 함께. 신호 · 검색어는 아래 둘로 나눠 쓴다.
  function detectionEngines(cve) {
    const engines = [...(cve.rule_engines || [])];
    if (cve.has_nuclei_template && !engines.includes('nuclei')) engines.push('nuclei');
    return engines;
  }

  // 탐지 룰 엔진만 (점검 템플릿 제외) — PUBLIC_DETECTION 과 엔진별 검색어가 쓴다.
  function ruleEngines(cve) {
    return detectionEngines(cve).filter(e => !isCheck(e));
  }

  // 점검 템플릿(nuclei)이 있는가 — nuclei 색인에서 왔든 룰 색인에서 왔든.
  function hasCheckTemplate(cve) {
    return detectionEngines(cve).some(isCheck);
  }

  // 탐지 룰 엔진 계열 키(RULE_FAMILIES 순서). 계열을 모르는 엔진은 넣지 않는다.
  function ruleFamilies(cve) {
    const found = new Set(ruleEngines(cve));
    return RULE_FAMILIES.filter(f => f.engines.some(e => found.has(e))).map(f => f.key);
  }

  // 공개 탐지 룰 — 탐지 룰 엔진이 하나라도 있으면 yes. 룰이 있다고만 기록되고(has_official_rules) 어떤 룰인지 남지
  // 않은 행은 nuclei 였을 수도 있어 단정하지 않는다(unknown, 실측 2026-11-23 0건).
  function detectionState(cve) {
    if (ruleEngines(cve).length) return 'yes';
    return cve.has_official_rules && !detectionEngines(cve).length ? 'unknown' : 'no';
  }

  // lifecycle: { entries, unresolved, untracked, partial } (lifecycle.js reduceMatch 결과) · products · today
  function lifecycleFacts(lc, products, today, affectedCount) {
    const counts = { ACTIVE: 0, SECURITY_SUPPORT: 0, EXTENDED_SUPPORT: 0, EOL: 0, UNKNOWN: 0 };
    const reasons = [];
    if (!lc) {
      if (!affectedCount) reasons.push('no_affected');
      else reasons.push('lifecycle_unloaded');
      return { state: 'unknown', counts, reasons, releases: 0 };
    }
    for (const e of lc.entries || []) counts[LC.statusOf(e.rel, (products || {})[e.slug], today)]++;
    counts.UNKNOWN += (lc.unresolved || []).length;
    const releases = (lc.entries || []).length;
    if (!affectedCount) reasons.push('no_affected');
    if (lc.untracked) reasons.push('untracked');
    // partial: 사이클이 이어진 제품의 다른 항목이 사이클 미상 — 그 항목이 EOL 사이클일 수 있다.
    if ((lc.unresolved || []).length || (lc.partial || []).length) reasons.push('unresolved');
    if ((lc.entries || []).some(e => LC.statusOf(e.rel, (products || {})[e.slug], today) === 'UNKNOWN')) {
      reasons.push('status_unknown');
    }
    let state;
    if (counts.EOL > 0) state = 'yes';
    else if (releases > 0 && !reasons.length) state = 'no';
    else state = 'unknown';
    return { state, counts, reasons: state === 'yes' ? [] : reasons, releases };
  }

  // 목록·검색·통계용 판정. deps: { packages, lifecycle, products, today, affectedCount }
  function signals(cve, deps) {
    const d = deps || {};
    const f = scoreFacts(cve);
    const ssvcExp = cve.ssvc_exploitation || null;
    const auto = cve.ssvc_automatable || null;
    const lcf = lifecycleFacts(d.lifecycle, d.products, d.today,
                               d.affectedCount != null ? d.affectedCount : (cve.affected || []).length);
    const s = {
      EXPLOITATION_CONFIRMED: t(cve.is_kev || cve.is_vulncheck_kev || ssvcExp === 'active'),
      CISA_KEV: t(cve.is_kev),
      PUBLIC_EXPLOIT: t(cve.has_public_exploit || cve.has_metasploit_module || cve.has_poc),
      AUTOMATABLE: auto === 'yes' ? 'yes' : auto === 'no' ? 'no' : 'unknown',
      RANSOMWARE: cve.is_kev_ransomware ? 'yes' : 'unknown',
      EOL_AFFECTED: lcf.state,
      PATCH_AVAILABLE: patchState(d.packages),
      PUBLIC_DETECTION: detectionState(cve),
      HIGH_EPSS: epssHigh(cve),
      CRITICAL_CVSS: f.cvss === null ? 'unknown' : t(f.cvss >= CVSS_CRITICAL),
    };
    return { states: s, lifecycle: lcf };
  }

  // 출처 하나 단위의 사실 — KPI·출처 화면이 센다. 신호(위)는 이것들을 증거 유형으로 묶은 것이다.
  // weaponized: 무기화된 exploit 코드 = Metasploit 모듈 ∪ Exploit-DB. PoC 저장소와 nuclei(점검 템플릿)는 넣지 않는다.
  // nuclei: 점검 템플릿이 있는 CVE(룰 색인에만 있는 것 포함, has:nuclei 와 같다).
  const SOURCE_FLAGS = ['cisa_kev', 'vulncheck_kev', 'ssvc_active', 'ssvc_assessed', 'metasploit', 'exploit_db',
                        'weaponized', 'poc', 'nuclei', 'ai_discovered', 'epss_scored', 'cvss_scored'];

  function sourceFlags(cve) {
    const msf = !!cve.has_metasploit_module, edb = !!cve.has_public_exploit;
    const f = scoreFacts(cve);
    return {
      cisa_kev: !!cve.is_kev, vulncheck_kev: !!cve.is_vulncheck_kev, ssvc_active: cve.ssvc_exploitation === 'active',
      ssvc_assessed: !!(cve.ssvc_exploitation || cve.ssvc_automatable), metasploit: msf, exploit_db: edb,
      weaponized: msf || edb, poc: !!cve.has_poc, nuclei: hasCheckTemplate(cve), ai_discovered: !!cve.ai_discovered,
      epss_scored: f.epss !== null, cvss_scored: f.cvss !== null,
    };
  }

  /* ---------- 출처 간 차이 (§20) — 어느 쪽도 지우지 않고 표시한다 ---------- */

  const sevBand = s => (s >= 9 ? 'Critical' : s >= 7 ? 'High' : s >= 4 ? 'Medium' : s > 0 ? 'Low' : 'None');

  const CONFLICTS = [
    { code: 'EXPLOITATION_SSVC', key: 'exploitation', subject: '악용 근거',
      label: 'KEV에는 있는데 CISA SSVC 판정은 Exploitation: active가 아님',
      rule: '한 출처라도 악용을 보고하면 악용 근거가 있는 것으로 봅니다. SSVC 판정 시점은 수집하지 않아 어느 쪽이 최신인지는 알 수 없습니다' },
    { code: 'EXPLOIT_SSVC', key: 'exploit', subject: '공개 익스플로잇',
      label: 'CISA SSVC 판정은 Exploitation: none(공개 PoC 없음)인데 Exploit-DB · Metasploit · PoC 목록에 있음',
      rule: '공개 목록에 있으면 공개 익스플로잇이 있는 것으로 봅니다. SSVC 판정 뒤에 공개됐을 수 있습니다' },
    { code: 'CVSS_VERSIONS', key: 'cvss', subject: 'CVSS',
      label: 'CVSS 버전(4.0 · 3.x)마다 심각도 등급이 다름',
      rule: '대표값은 가장 높은 점수입니다(같으면 4.0 → 3.1 → 3.0 순). 다른 버전 점수도 함께 보여 줍니다' },
  ];
  const CONFLICT = Object.fromEntries(CONFLICTS.map(c => [c.code, c]));

  function conflictsOf(cve) {
    const out = [];
    const ssvc = cve.ssvc_exploitation || null;
    if ((cve.is_kev || cve.is_vulncheck_kev) && ssvc && ssvc !== 'active') out.push('EXPLOITATION_SSVC');
    if (ssvc === 'none' && (cve.has_public_exploit || cve.has_metasploit_module || cve.has_poc)) out.push('EXPLOIT_SSVC');
    const alt = cve.cvss_alt || {};
    if (new Set(Object.values(alt).filter(v => Number(v) > 0).map(sevBand)).size > 1) out.push('CVSS_VERSIONS');
    return out;
  }

  function conflictQuery(conflicts, value) {
    const v = String(value || '').toLowerCase();
    if (v === 'any') return conflicts.length > 0;
    const c = CONFLICTS.find(x => x.key === v || x.code.toLowerCase() === v.replace(/-/g, '_'));
    return !!c && conflicts.includes(c.code);
  }

  function correlationsOf(states) {
    return CORRELATIONS.filter(c => c.parts.every(p =>
      p[0] === '!' ? states[p.slice(1)] === 'no' : states[p] === 'yes')).map(c => c.code);
  }

  function reasonsOf(cve, states, lcf) {
    const r = {};
    if (states.CRITICAL_CVSS === 'unknown') r.CRITICAL_CVSS = ['cvss_unscored'];
    if (states.HIGH_EPSS === 'unknown') r.HIGH_EPSS = ['epss_unscored'];
    if (states.AUTOMATABLE === 'unknown') r.AUTOMATABLE = ['ssvc_missing'];
    if (states.RANSOMWARE === 'unknown') r.RANSOMWARE = [cve.is_kev ? 'kev_unknown' : 'not_in_kev'];
    if (states.PATCH_AVAILABLE === 'unknown') r.PATCH_AVAILABLE = ['no_osv_record'];
    if (states.EOL_AFFECTED === 'unknown') r.EOL_AFFECTED = lcf.reasons.slice();
    if (states.PUBLIC_DETECTION === 'unknown') r.PUBLIC_DETECTION = ['rules_unlisted'];
    return r;
  }

  /* ---------- 상세용 근거 행렬 (출처마다 hit · miss · unknown · info) ---------- */

  // sid: 출처 엔티티 id (entities.js SOURCES) — 표시 이름이 바뀌어도 출처와의 관계는 유지된다.
  const SID = { 'CISA KEV': 'cisa-kev', 'VulnCheck KEV': 'vulncheck-kev', 'CISA SSVC': 'cisa-adp', 'Exploit-DB': 'exploit-db',
                Metasploit: 'metasploit', 'PoC-in-GitHub': 'poc-in-github', OSV: 'osv', '공개 룰 색인': 'rule-index' };
  const ENGINE_SID = { sigma: 'sigma', splunk: 'splunk', yara: 'yara', snort2: 'et-open', snort3: 'et-open',
                       suricata5: 'et-open', suricata7: 'et-open', nuclei: 'nuclei' };

  /* ---------- 탐지 룰 라이선스 ----------
   * export(src/rule_license.py)가 룰마다 license · link_only 를, YARA 는 license_url · holder(저작권 문구)까지 적는다. 화면은 그 값을 쓰되,
   * 출처가 정해진 룰은 아래 표로 표기한다 — 옛 색인이 남긴 표기(ET Open 'MIT', YARA '룰별 상이')를 바로잡기 위해서다.
   * body: 룰 본문을 실어도 되는가. nuclei 는 점검 템플릿이라 늘 링크만, YARA 는 원 저장소에 LICENSE 가 있을 때만. */
  const RULE_LICENSE = {
    sigma: { license: 'DRL 1.1', url: 'https://github.com/SigmaHQ/Detection-Rule-License' },
    splunk: { license: 'Apache-2.0', url: 'https://github.com/splunk/security_content/blob/develop/LICENSE' },
    nuclei: { license: 'MIT', url: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md' },
    'et-open': { license: 'BSD', url: 'https://rules.emergingthreats.net/open/suricata-7.0/LICENSE', holder: '© 2003-2026 Emerging Threats' },
    'snort-community': { license: 'GPLv2', url: 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.html',
                         holder: '© 2001-2026 Sourcefire, Inc. 및 각 작성자' },
  };
  const LEGACY_LICENSE = new Set(['룰별 상이']);
  const httpUrl = u => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '');

  // 룰이 온 곳 — 네트워크 룰은 엔진이 같아도 ET Open(BSD)과 Snort Community(GPLv2)의 라이선스가 다르다.
  function ruleSource(rule) {
    const r = rule || {};
    if (NETWORK.has(r.engine)) return /community/i.test(r.source || '') ? 'snort-community' : 'et-open';
    return ENGINE_SID[r.engine] || null;
  }

  function ruleTerms(rule) {
    const r = rule || {};
    const sid = ruleSource(r);
    const stored = String(r.license || '').trim();
    if (r.engine === 'yara') {
      // 저작권 문구(holder)는 export 가 원 저장소 LICENSE 에서 옮겨 적은 것 — BSD · MIT 저장소만 있다.
      const licenseUrl = httpUrl(r.license_url);
      return { sid, license: LEGACY_LICENSE.has(stored) ? '' : stored, licenseUrl, holder: String(r.holder || '').trim(),
               body: !r.link_only && !!licenseUrl, ruleUrl: httpUrl(r.url) };
    }
    const base = RULE_LICENSE[sid] || {};
    return { sid, license: base.license || stored, licenseUrl: base.url || httpUrl(r.license_url), holder: base.holder || '',
             body: !r.link_only && r.engine !== 'nuclei', ruleUrl: httpUrl(r.url) };
  }

  /* ---------- 탐지 룰 원문 링크 ----------
   * Sigma · Splunk · YARA · nuclei 는 원 저장소에 룰마다 파일이 있어 색인이 준 url 을 쓴다.
   * ET Open · Snort Community 는 룰을 묶음 파일로만 배포해 룰마다 된 주소가 없다 — 색인은 url 을 비워 두고, 화면이 룰 본문으로 만든다.
   *   Snort Community: snort.org 룰 문서 /rule-docs/<gid>-<sid>. 2026-09-30 실측으로 데이터의 SID 22개 중 20개에 문서가 있고,
   *     나머지는 snort.org 의 '문서 없음' 화면이 열린다.
   *   ET Open: 룰이 든 공식 분류 파일 + SID 위치(텍스트 조각 '#:~:text=sid:N;'). 크롬 계열에서 그 줄로 옮겨 가는 것을 확인했고,
   *     다른 브라우저는 확인하지 않았다(지원하지 않으면 파일 처음이 열린다). 분류는 msg 앞머리('ET WEB_SPECIFIC_APPS …')다 —
   *     2026-09-30 배포본에서 데이터의 ET 룰 2,972개가 모두 이 규칙으로 찾은 파일에 들어 있었다. 표에 없는 분류는 링크를 달지 않는다
   *     (없는 파일로 보내지 않게). 크기(MB)는 그날 배포본(emerging.rules.tar.gz)을 잰 값이라 대략이다. IP 평판 파일(botcc · ciarmy ·
   *     compromised · drop · dshield · tor)은 CVE 참조가 없어(실측 0건) 뺐다. */
  const ET_DIR = { snort2: 'snort-2.9.0', suricata5: 'suricata-5.0', suricata7: 'suricata-7.0' };
  const ET_SURICATA = {
    activex: 0.4, adware_pup: 0.7, attack_response: 0.7, chat: 0.0, coinminer: 0.0, current_events: 0.1, deleted: 1.8,
    dns: 0.0, dos: 0.1, exploit: 1.5, exploit_kit: 3.8, ftp: 0.1, games: 0.0, hunting: 0.9, icmp: 0.0, icmp_info: 0.0,
    imap: 0.0, inappropriate: 0.0, info: 6.5, ja3: 0.1, malware: 17.7, misc: 0.0, mobile_malware: 0.8, netbios: 0.4,
    p2p: 0.1, phishing: 2.2, policy: 0.6, pop3: 0.0, retired: 0.4, rpc: 0.1, scada: 0.1, scan: 0.2, shellcode: 0.1,
    smtp: 0.0, snmp: 0.0, sql: 0.2, telnet: 0.0, tftp: 0.0, user_agents: 0.2, voip: 0.0, web_client: 0.5, web_server: 0.5,
    web_specific_apps: 5.7, worm: 0.0,
  };
  const ET_FILES = {
    'snort-2.9.0': {
      activex: 0.4, attack_response: 0.7, chat: 0.0, current_events: 7.0, deleted: 1.6, dns: 0.0, dos: 0.1, exploit: 1.4,
      ftp: 0.1, games: 0.0, icmp: 0.0, icmp_info: 0.0, imap: 0.0, inappropriate: 0.0, info: 8.2, malware: 0.6, misc: 0.0,
      mobile_malware: 0.9, netbios: 0.4, p2p: 0.1, policy: 0.6, pop3: 0.0, retired: 0.4, rpc: 0.1, scada: 0.1, scan: 0.2,
      shellcode: 0.1, smtp: 0.0, snmp: 0.0, sql: 0.2, telnet: 0.0, tftp: 0.0, trojan: 19.1, user_agents: 0.2, voip: 0.0,
      web_client: 0.5, web_server: 0.5, web_specific_apps: 5.8, worm: 0.0,
    },
    'suricata-5.0': ET_SURICATA,
    'suricata-7.0': ET_SURICATA,
  };

  // 룰 본문의 SID — Snort 는 gid:sid 로 문서를 찾는다(gid 를 적지 않은 룰은 1).
  function ruleSid(rule) {
    const code = String((rule || {}).code || '');
    const sid = (/\bsid\s*:\s*(\d+)/.exec(code) || [])[1];
    return sid ? { sid, gid: (/\bgid\s*:\s*(\d+)/.exec(code) || [])[1] || '1' } : null;
  }

  // 룰 한 개의 원문 링크 — { url, text, size(MB · ET 분류 파일만), title } 또는 null.
  function ruleLink(rule, cve) {
    const r = rule || {};
    const own = httpUrl(r.url);
    if (r.engine === 'nuclei') {
      const u = httpUrl((cve || {})._nuclei_url) || own;
      return u ? { url: u, text: '원문', size: null, title: 'nuclei-templates의 템플릿 원문' } : null;
    }
    if (own || !NETWORK.has(r.engine)) return own ? { url: own, text: '원문', size: null, title: '원 저장소의 룰 원문' } : null;
    const id = ruleSid(r);
    if (ruleSource(r) === 'snort-community') {
      return id ? { url: `https://www.snort.org/rule-docs/${id.gid}-${id.sid}`, text: '룰 설명', size: null,
                    title: "snort.org 룰 문서(설명 · 관련 CVE · 대응). 문서가 아직 없는 룰은 snort.org의 '문서 없음' 화면이 열립니다" } : null;
    }
    const dir = ET_DIR[r.engine];
    const files = dir ? ET_FILES[dir] : null;
    const cat = ((/msg\s*:\s*"ET ([A-Z0-9_]+)/.exec(String(r.code || '')) || [])[1] || '').toLowerCase();
    if (!files || !cat || !Object.prototype.hasOwnProperty.call(files, cat)) return null;
    const file = `emerging-${cat}.rules`, size = files[cat];
    return { url: `https://rules.emergingthreats.net/open/${dir}/rules/${file}${id ? `#:~:text=sid:${id.sid};` : ''}`,
             text: '원문 파일', size, file,
             title: `ET Open 공식 분류 파일 ${file}(${size < 1 ? '1MB 미만' : `약 ${size}MB`}, 2026-09-30 기준)${
               id ? `. 크롬 계열 브라우저에서는 SID ${id.sid} 줄로 바로 옮겨 갑니다` : ''}` };
  }

  const row = (source, status, value, extra) => {
    const r = Object.assign({ source, status, value }, extra || {});
    r.sid = r.sid || SID[source] || (r.engine && ENGINE_SID[r.engine]) || null;
    return r;
  };

  function exploitationRows(cve) {
    const id = cve.id;
    const ssvc = cve.ssvc_exploitation || null;
    return [
      cve.is_kev
        ? row('CISA KEV', 'hit', '등재', { kind: 'listing', url: URL.kev, basis: 'CVE ID',
                                           detail: cve.kev_due_date ? `미국 연방기관 조치 기한 ${cve.kev_due_date}` : '' })
        : row('CISA KEV', 'miss', '미등재', { kind: 'listing', url: URL.kev, basis: 'CVE ID' }),
      cve.is_vulncheck_kev
        ? row('VulnCheck KEV', 'hit', '등재', { kind: 'listing', url: URL.vulncheck, basis: 'CVE ID' })
        : row('VulnCheck KEV', 'miss', '미등재', { kind: 'listing', url: URL.vulncheck, basis: 'CVE ID' }),
      ssvc === 'active'
        ? row('CISA SSVC', 'hit', 'Exploitation: active', { kind: 'assessment', url: URL.cveRecord(id), basis: 'CVE ID' })
        : ssvc
          ? row('CISA SSVC', 'miss', `Exploitation: ${ssvc}`, { kind: 'assessment', url: URL.cveRecord(id), basis: 'CVE ID' })
          : row('CISA SSVC', 'unknown', '판정 없음', { kind: 'assessment', basis: 'CVE ID' }),
    ];
  }

  function weaponizationRows(cve) {
    const rows = [];
    rows.push(cve.has_public_exploit
      ? row('Exploit-DB', 'hit', '항목 있음', { kind: 'artifact', url: cve._exploit_db_url || URL.exploitdb,
                                                 basis: 'CVE ID', detail: '원문은 싣지 않고 링크만 둡니다' })
      : row('Exploit-DB', 'miss', '항목 없음', { kind: 'artifact', basis: 'CVE ID' }));
    const mods = (cve.metasploit_modules || []).filter(Boolean);
    rows.push(cve.has_metasploit_module
      ? row('Metasploit', 'hit', mods.length ? `모듈 ${mods.length}개` : '모듈 있음',
            { kind: 'artifact', url: URL.metasploit, basis: 'CVE ID', items: mods })
      : row('Metasploit', 'miss', '모듈 없음', { kind: 'artifact', basis: 'CVE ID' }));
    const pocs = [...new Set((cve.poc_urls || []).filter(Boolean))];
    // 저장소 수는 export 때 PoC 색인에서 센 값(poc_count)이 있으면 그것 — 링크는 판정 때 실은 앞 3개뿐이다.
    const pocTotal = Math.max(Number(cve.poc_count) || 0, pocs.length);
    rows.push(cve.has_poc
      ? row('PoC-in-GitHub', 'hit', pocTotal ? `공개 저장소 ${pocTotal}개` : '공개 PoC 있음',
            { kind: 'artifact', url: URL.poc, basis: 'CVE ID', links: pocs,
              detail: `${pocTotal > pocs.length ? `링크는 앞 ${pocs.length}개만 싣습니다. ` : ''}PoC가 공개됐다는 뜻이며 실제 공격이 있었다는 뜻은 아닙니다` })
      : row('PoC-in-GitHub', 'miss', '없음', { kind: 'artifact', basis: 'CVE ID' }));
    if (cve.ssvc_exploitation === 'poc') {
      rows.push(row('CISA SSVC', 'info', 'Exploitation: poc', { kind: 'assessment', url: URL.cveRecord(cve.id),
        basis: 'CVE ID', detail: 'CISA 판정: 공개 PoC나 잘 알려진 공격 방법이 있음 (개별 익스플로잇 링크는 아님)' }));
    }
    return rows;
  }

  function automationRows(cve) {
    const a = cve.ssvc_automatable || null;
    const rows = [a === 'yes'
      ? row('CISA SSVC', 'hit', 'Automatable: yes', { kind: 'assessment', url: URL.cveRecord(cve.id), basis: 'CVE ID',
                                                       detail: '정찰부터 공격까지 자동화할 수 있어 대량 스캔 대상이 되기 쉽습니다' })
      : a
        ? row('CISA SSVC', 'miss', `Automatable: ${a}`, { kind: 'assessment', url: URL.cveRecord(cve.id), basis: 'CVE ID' })
        : row('CISA SSVC', 'unknown', '판정 없음', { kind: 'assessment', basis: 'CVE ID' })];
    if (cve.ssvc_technical_impact) {
      rows.push(row('CISA SSVC', 'info', `Technical Impact: ${cve.ssvc_technical_impact}`, {
        kind: 'assessment', url: URL.cveRecord(cve.id), basis: 'CVE ID',
        detail: cve.ssvc_technical_impact === 'total' ? '공격에 성공하면 시스템 전체를 제어할 수 있음' : '영향이 일부에 그침' }));
    }
    return rows;
  }

  function ransomwareRows(cve) {
    if (cve.is_kev_ransomware) {
      return [row('CISA KEV', 'hit', '랜섬웨어 캠페인 사용: Known', { kind: 'listing', url: URL.kev, basis: 'CVE ID' })];
    }
    return [row('CISA KEV', 'unknown', cve.is_kev ? '랜섬웨어 캠페인 사용: Unknown' : 'KEV 미등재',
                { kind: 'listing', url: URL.kev, basis: 'CVE ID' })];
  }

  function ruleInfo(cve, engine) {
    const rules = cve.rules || {};
    if (NETWORK.has(engine)) return (rules.network || []).filter(r => (r.engine || 'network') === engine);
    return rules[engine] ? [rules[engine]] : [];
  }

  function detectionRows(cve) {
    const engines = detectionEngines(cve);
    const ordered = engines.slice().sort((a, b) =>
      (ENGINE_ORDER.indexOf(a) + 1 || 99) - (ENGINE_ORDER.indexOf(b) + 1 || 99));
    const rows = [];
    for (const engine of ordered) {
      const info = engineInfo(engine);
      // 같은 엔진이라도 룰이 온 곳이 다르면(ET Open · Snort Community) 라이선스가 달라 행을 나눈다.
      const bySource = new Map();
      for (const r of ruleInfo(cve, engine)) {
        const sid = ruleSource(Object.assign({ engine }, r));
        if (!bySource.has(sid)) bySource.set(sid, []);
        bySource.get(sid).push(r);
      }
      if (!bySource.size) bySource.set(ENGINE_SID[engine] || null, []);
      for (const [sid, found] of bySource) {
        const first = found[0] || {};
        const terms = ruleTerms(Object.assign({ engine }, first));
        // 링크는 첫 룰의 원문 — ET Open · Snort Community 는 색인에 주소가 없어 룰 본문으로 만든다(ruleLink).
        const link = ruleLink(Object.assign({ engine }, first), cve);
        const url = link ? link.url : '';
        rows.push(row(info.label, 'hit', info.kind === 'check' ? '점검 템플릿' : found.length > 1 ? `룰 ${found.length}개` : '룰',
                      { kind: info.kind, engine, url, basis: 'CVE ID', sid: sid || undefined, source_name: first.source || info.source,
                        license: terms.license, author: first.author || '', count: found.length || 1,
                        detail: info.kind === 'check'
                          ? '대상에 요청을 보내 취약 여부를 확인하는 템플릿입니다. 공격 탐지 룰이 아니며 공격에도 쓰일 수 있습니다'
                          : '' }));
      }
    }
    if (!rows.length) {
      rows.push(cve.has_official_rules
        ? row('공개 룰 색인', 'unknown', '어떤 룰인지 기록 없음', { kind: 'detect', basis: 'CVE ID',
            detail: '공개 룰이 있다고만 기록돼 있고 엔진과 룰 내용이 남아 있지 않습니다. nuclei 점검 템플릿일 수도 있어 탐지 룰로 세지 않습니다' })
        : row('공개 룰 색인', 'miss', '색인된 공개 룰 없음',
              { kind: 'detect', basis: 'CVE ID', detail: 'Sigma · ET/Snort · Suricata · Splunk · YARA · nuclei에서 찾음' }));
    }
    return rows;
  }

  function fixedVersions(pkgMap) {
    const out = [];
    for (const [pkg, ecoMap] of Object.entries(pkgMap || {})) {
      for (const [eco, fixes] of Object.entries(ecoMap || {})) {
        const f = (fixes || []).filter(Boolean);
        if (f.length) out.push({ package: pkg, ecosystem: eco, versions: f });
      }
    }
    return out;
  }

  function remediationRows(cve, pkgMap) {
    const rows = [];
    const state = patchState(pkgMap);
    const fixed = fixedVersions(pkgMap);
    if (state === 'yes') {
      rows.push(row('OSV', 'hit', `수정 버전 ${fixed.length}건`, { kind: 'record', url: URL.osv(cve.id), basis: 'CVE ID·별칭',
        fixed, packages: Object.keys(pkgMap || {}) }));
    } else if (state === 'no') {
      rows.push(row('OSV', 'miss', '수정 버전 기록 없음', { kind: 'record', url: URL.osv(cve.id), basis: 'CVE ID·별칭',
        packages: Object.keys(pkgMap || {}), detail: 'OSV에 영향 패키지는 있지만 수정 버전이 기록되지 않았습니다' }));
    } else {
      rows.push(row('OSV', 'unknown', 'OSV 기록 없음', { kind: 'record', basis: 'CVE ID·별칭',
        detail: 'OSV가 다루지 않는 제품이거나 아직 수집 전입니다. 패치가 없다는 뜻은 아닙니다' }));
    }
    if (cve.is_kev && cve.kev_due_date) {
      rows.push(row('CISA KEV', 'info', `미 연방기관 기한 ${cve.kev_due_date}`, { kind: 'listing', url: URL.kev, basis: 'CVE ID',
        detail: 'CISA가 미국 연방 민간기관에 정한 패치·완화 기한. 다른 기관 · 기업의 의무 기한은 아닙니다' }));
    }
    return rows;
  }

  function lifecycleRows(lc, products, today) {
    const rows = [];
    for (const e of (lc && lc.entries) || []) {
      const meta = (products || {})[e.slug] || {};
      const status = LC.statusOf(e.rel, meta, today);
      rows.push(row(meta.label || e.slug, status === 'EOL' ? 'hit' : status === 'UNKNOWN' ? 'unknown' : 'miss', status, {
        sid: 'endoflife', kind: 'mapping', slug: e.slug, cycle: e.rel.cycle, rel: e.rel, vendor: meta.vendor || '',
        eol_date: e.rel.eol_date || null, via: e.via, key: e.key, basis: e.basis || null,
        url: meta.source_url || URL.endoflife, original_url: meta.original_source_url || '',
        fetched_at: e.rel.fetched_at || meta.fetched_at || null,
        match: e.via === 'override' ? 'explicit' : 'automatic' }));
    }
    return rows;
  }

  // 상세 화면의 전체 맥락. deps: signals() 와 같음 + match(항목별 매칭) + affected(전체 영향 제품)
  function derive(cve, deps) {
    const d = deps || {};
    const affected = d.affected || cve.affected || [];
    const base = signals(cve, Object.assign({}, d, { affectedCount: affected.length }));
    const s = base.states;
    const f = scoreFacts(cve);
    const group = (code, rows, extra) => Object.assign({ state: s[code], rows }, extra || {});
    return {
      id: cve.id,
      states: s,
      correlations: correlationsOf(s),
      reasons: reasonsOf(cve, s, base.lifecycle),
      scores: {
        cvss: { value: f.cvss, version: cve.cvss_version || null, severity: cve.severity || 'None',
                vector: cve.cvss_vector && cve.cvss_vector !== 'N/A' ? cve.cvss_vector : null,
                alt: cve.cvss_alt || {}, sources: [{ name: 'CVE 레코드', url: URL.cveRecord(cve.id) },
                                                    { name: 'NVD', url: URL.nvd(cve.id) }] },
        epss: { value: f.epss, percentile: f.percentile, high: s.HIGH_EPSS, source: { name: 'FIRST EPSS', url: URL.epss(cve.id) } },
      },
      exploitation: group('EXPLOITATION_CONFIRMED', exploitationRows(cve), { kev: s.CISA_KEV }),
      weaponization: group('PUBLIC_EXPLOIT', weaponizationRows(cve)),
      automation: group('AUTOMATABLE', automationRows(cve)),
      ransomware: group('RANSOMWARE', ransomwareRows(cve)),
      detection: group('PUBLIC_DETECTION', detectionRows(cve)),
      remediation: group('PATCH_AVAILABLE', remediationRows(cve, d.packages), { fixed: fixedVersions(d.packages) }),
      lifecycle: group('EOL_AFFECTED', lifecycleRows(d.lifecycle, d.products, d.today), {
        counts: base.lifecycle.counts, unresolved: (d.lifecycle && d.lifecycle.unresolved) || [],
        partial: (d.lifecycle && d.lifecycle.partial) || [],
        untracked: d.lifecycle ? d.lifecycle.untracked : affected.length }),
      discovery: cve.ai_discovered
        ? { program: cve.ai_program || '', detail: cve.ai_detail || '', url: cve.ai_url || '' } : null,
      record: { published: cve.published || '', updated: cve.updated || '', date: cve.date || '' },
    };
  }

  /* ---------- 검색어 (has: · no: · unknown: · corr: · release:) ---------- */

  function stateQuery(states, value, want) {
    const code = SIGNAL_BY_KEY[String(value || '').toLowerCase()];
    return !!code && states[code] === want;
  }

  function correlationQuery(correlations, value) {
    const code = String(value || '').toUpperCase().replace(/-/g, '_');
    return !!CORRELATION[code] && correlations.includes(code);
  }

  function parseRelease(value) {
    const m = /^([a-z0-9][a-z0-9.+-]*)\/(.+)$/.exec(String(value || '').toLowerCase());
    return m ? { slug: m[1], cycle: m[2] } : null;
  }

  /* ---------- 집계 (대시보드 · 수명주기 화면) ---------- */

  function emptyCounts() {
    const out = {};
    for (const sgl of SIGNALS) out[sgl.code] = { yes: 0, no: 0, unknown: 0 };
    return out;
  }

  // 동시 발생 행렬의 축 — 신호 둘이 함께 yes 인 CVE 수. 점수가 아니라 건수다.
  const MATRIX = ['CISA_KEV', 'PUBLIC_EXPLOIT', 'AUTOMATABLE', 'RANSOMWARE', 'EOL_AFFECTED', 'CRITICAL_CVSS',
                  'HIGH_EPSS', 'PATCH_AVAILABLE', 'PUBLIC_DETECTION'];

  // 신호 yes 를 고르는 검색어 — 대시보드 숫자를 누르면 이 검색어로 목록이 열린다(상관 카드와 같은 표기).
  function yesQuery(code) {
    if (code === 'CRITICAL_CVSS') return 'cvss:>=9';
    if (code === 'EOL_AFFECTED') return 'lifecycle:eol';
    return `has:${SIGNAL[code].key}`;
  }

  // export 의 daily_trend 와 같은 창 — 기준 시각(UTC)의 날짜까지 n 일.
  function trendDays(endIso, n) {
    const end = new Date(endIso);
    if (isNaN(end)) return [];
    const base = Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate());
    return Array.from({ length: n || 30 }, (_, i) => new Date(base - ((n || 30) - 1 - i) * 864e5).toISOString().slice(0, 10));
  }

  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'None'];

  // items: [{ id, states, correlations, releases: ['slug|cycle', ...], productOnly, flags, conflicts, published, severity }]
  // correlation_scope: 첫 사실이 yes 이고 둘째 사실을 알 수 있는(unknown 이 아닌) CVE 수 — 상관 건수의 분모.
  // opts.days: 일별 심각도 막대의 날짜 목록 (trendDays)
  function aggregate(items, opts) {
    const o = opts || {};
    const sourcesOut = Object.fromEntries(SOURCE_FLAGS.map(k => [k, 0]));
    const conflictsOut = Object.fromEntries(CONFLICTS.map(c => [c.code, 0]));
    const cooccur = {};
    for (let i = 0; i < MATRIX.length; i++) for (let j = i + 1; j < MATRIX.length; j++) cooccur[`${MATRIX[i]}|${MATRIX[j]}`] = 0;
    const dayIndex = new Map((o.days || []).map((d, i) => [d, i]));
    const daily = (o.days || []).map(date => Object.assign({ date }, Object.fromEntries(SEVERITIES.map(s => [s, 0]))));
    const signalsOut = emptyCounts();
    const corr = Object.fromEntries(CORRELATIONS.map(c => [c.code, 0]));
    const scope = Object.fromEntries(CORRELATIONS.map(c => [c.code, 0]));
    const releases = {};
    const products = {};
    const lifecycle = { mapped: 0, cycle_level: 0, product_only: 0 };
    const tally = (bucket, key, st) => {
      const r = bucket[key] || (bucket[key] = { cves: 0, kev: 0, exploited: 0, exploit: 0, detection: 0, patch: 0, critical: 0 });
      r.cves++;
      if (st.CISA_KEV === 'yes') r.kev++;
      if (st.EXPLOITATION_CONFIRMED === 'yes') r.exploited++;
      if (st.PUBLIC_EXPLOIT === 'yes') r.exploit++;
      if (st.PUBLIC_DETECTION === 'yes') r.detection++;
      if (st.PATCH_AVAILABLE === 'yes') r.patch++;
      if (st.CRITICAL_CVSS === 'yes') r.critical++;
    };
    for (const it of items) {
      for (const [code, st] of Object.entries(it.states)) signalsOut[code][st]++;
      for (const c of it.correlations) corr[c]++;
      for (const c of CORRELATIONS) {
        const [first, second] = c.parts;
        if (it.states[first] === 'yes' && it.states[second.replace('!', '')] !== 'unknown') scope[c.code]++;
      }
      if (it.releases && it.releases.length) lifecycle.cycle_level++;
      else if (it.productOnly) lifecycle.product_only++;
      // 릴리스별은 연결마다, 제품별은 CVE 하나를 한 번만 센다.
      for (const key of it.releases || []) tally(releases, key, it.states);
      for (const slug of new Set((it.releases || []).map(k => k.split('|')[0]))) tally(products, slug, it.states);
      if (it.flags) for (const k of SOURCE_FLAGS) if (it.flags[k]) sourcesOut[k]++;
      for (const c of it.conflicts || []) conflictsOut[c]++;
      const yes = MATRIX.filter(c => it.states[c] === 'yes');
      for (let i = 0; i < yes.length; i++) for (let j = i + 1; j < yes.length; j++) cooccur[`${yes[i]}|${yes[j]}`]++;
      const di = dayIndex.get(String(it.published || '').slice(0, 10));
      if (di !== undefined) daily[di][SEVERITIES.includes(it.severity) ? it.severity : 'None']++;
    }
    lifecycle.mapped = lifecycle.cycle_level + lifecycle.product_only;
    return { total: items.length, signals: signalsOut, correlations: corr, correlation_scope: scope,
             releases, products, lifecycle, sources: sourcesOut, conflicts: conflictsOut, cooccur, daily };
  }

  // 최근 공개 — CVE 공개일(published, 날짜 단위) 순, 같은 날이면 Argus 시각(date) 순.
  // date(알림 시각, 없으면 행 갱신 시각)만으로 세우면 재평가된 옛 CVE 가 맨 위로 온다(실측 CVE-2019-8720).
  // date 는 시간대가 섞여 있어(+09:00 등) 문자열이 아니라 시각으로 비교한다.
  const RECENT_SIGNALS = ['CISA_KEV', 'EXPLOITATION_CONFIRMED', 'PUBLIC_EXPLOIT', 'AUTOMATABLE', 'RANSOMWARE',
                          'EOL_AFFECTED'];
  function recentOf(cves, contextOf, n) {
    const at = c => { const t = Date.parse(c.date || ''); return isNaN(t) ? -Infinity : t; };
    const pub = c => String(c.published || '');
    return cves.filter(c => /^\d{4}-\d{2}-\d{2}$/.test(pub(c)))
      .sort((a, b) => (pub(a) < pub(b) ? 1 : pub(a) > pub(b) ? -1 : 0) || at(b) - at(a)
                      || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .slice(0, n || 8)
      .map(c => {
        const x = contextOf(c) || { states: {}, correlations: [] };
        return { id: c.id, title: c.title || '', severity: c.severity || 'None', cvss: Number(c.cvss) || 0,
                 published: pub(c), date: c.date, correlations: x.correlations.slice(),
                 signals: RECENT_SIGNALS.filter(k => x.states[k] === 'yes') };
      });
  }

  // 집계 한 건 — 브라우저와 CI 가 같은 모양으로 만든다.
  function aggregateItem(cve, ctx, lc) {
    return {
      id: cve.id, states: ctx.states, correlations: ctx.correlations,
      releases: lc ? lc.entries.map(e => `${e.slug}|${e.rel.cycle}`) : [],
      productOnly: !!lc && !lc.entries.length && lc.unresolved.length > 0,
      flags: sourceFlags(cve), conflicts: conflictsOf(cve),
      published: cve.published || '', severity: cve.severity || 'None',
    };
  }

  /* ---------- 데이터 품질 점검 ---------- */

  const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
  const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

  // cves: cves.json 행 · packages: cve-packages 의 packages · lifecycle: lifecycle.json
  function qualityChecks(cves, deps) {
    const d = deps || {};
    const checks = [];
    // warn: 데이터끼리 어긋남(고칠 대상) · info: 원래 비어 있는 값(unknown 으로 표시하면 되는 것)
    const add = (id, label, bad, note, level) => checks.push({
      id, label, status: bad.length ? (level || 'warn') : 'ok', count: bad.length, examples: bad.slice(0, 5),
      note: note || '' });
    const ids = cves.map(c => c && c.id);
    add('cve_id_invalid', 'CVE ID 형식 오류', ids.filter(i => !CVE_ID.test(String(i || ''))));
    const seen = new Set(), dup = new Set();
    for (const i of ids) { if (seen.has(i)) dup.add(i); seen.add(i); }
    add('cve_duplicate', '중복 CVE', [...dup]);
    add('cvss_missing', 'CVSS 점수 없음 (미확인으로 표시)', cves.filter(c => !(Number(c.cvss) > 0)).map(c => c.id),
        '0점이 아니라 점수 없음으로 다룹니다', 'info');
    add('epss_missing', 'EPSS 미채점 (미확인으로 표시)',
        cves.filter(c => !(Number(c.epss) > 0) && !(Number(c.epss_percentile) > 0)).map(c => c.id),
        '0%가 아니라 채점 전으로 다룹니다', 'info');
    add('ssvc_missing', 'CISA SSVC 판정 없음 (미확인으로 표시)',
        cves.filter(c => !c.ssvc_exploitation && !c.ssvc_automatable).map(c => c.id), '', 'info');
    add('kev_ransom_without_kev', 'KEV 미등재인데 랜섬웨어 표시', cves.filter(c => c.is_kev_ransomware && !c.is_kev).map(c => c.id));
    add('kev_due_without_kev', 'KEV 미등재인데 조치 기한 있음', cves.filter(c => c.kev_due_date && !c.is_kev).map(c => c.id));
    add('kev_without_due', 'KEV 등재인데 조치 기한 없음', cves.filter(c => c.is_kev && !c.kev_due_date).map(c => c.id));
    add('edb_flag_without_url', 'Exploit-DB 표시가 있는데 링크 없음',
        cves.filter(c => c.has_public_exploit && !c._exploit_db_url).map(c => c.id));
    add('poc_flag_without_url', 'PoC 표시가 있는데 링크 없음', cves.filter(c => c.has_poc && !(c.poc_urls || []).length).map(c => c.id));
    add('poc_duplicate_url', 'PoC 링크 중복', cves.filter(c => {
      const u = (c.poc_urls || []).filter(Boolean);
      return new Set(u.map(x => x.toLowerCase().replace(/\/+$/, ''))).size !== u.length;
    }).map(c => c.id));
    add('msf_flag_without_module', 'Metasploit 표시가 있는데 모듈명 없음',
        cves.filter(c => c.has_metasploit_module && !(c.metasploit_modules || []).length).map(c => c.id));
    add('reference_duplicate', '참고 링크 중복', cves.filter(c => {
      const u = (c.references || []).filter(Boolean);
      return new Set(u).size !== u.length;
    }).map(c => c.id));
    // 값의 범위 · 형식 (§26)
    const num = v => (v === null || v === undefined || v === '' ? null : Number(v));
    add('cvss_out_of_range', 'CVSS가 0–10 밖', cves.filter(c => {
      const vals = [num(c.cvss), ...Object.values(c.cvss_alt || {}).map(num)].filter(v => v !== null);
      return vals.some(v => !(v >= 0 && v <= 10));
    }).map(c => c.id));
    add('epss_out_of_range', 'EPSS 확률·백분위가 0–1 밖', cves.filter(c =>
      [num(c.epss), num(c.epss_percentile)].some(v => v !== null && !(v >= 0 && v <= 1))).map(c => c.id));
    add('cwe_invalid', 'CWE 형식 오류 (CWE-숫자 아님)', cves.filter(c =>
      (c.cwe || []).some(w => !/^CWE-\d{1,4}$/.test(String(w)))).map(c => c.id));
    const badUrl = u => !/^https?:\/\/[^\s/$.?#][^\s]*$/i.test(String(u || ''));
    add('url_invalid', '링크 형식 오류 (공백 포함 · http/https 아님)', cves.filter(c => {
      const urls = [...(c.references || []), ...(c.poc_urls || []), c._exploit_db_url, c._nuclei_url, c.ai_url]
        .filter(u => u !== undefined && u !== null && u !== '');
      for (const v of Object.values(c.rules || {})) for (const r of Array.isArray(v) ? v : [v]) if (r && r.url) urls.push(r.url);
      return urls.some(badUrl);
    }).map(c => c.id), '공백처럼 인코딩되지 않은 문자가 있음. 브라우저는 대개 열지만 형식상 오류 (실측: YARA 룰 메타의 source_url)');
    // 출처 매핑 — 증거 행이 가리키는 출처 엔티티가 있어야 한다
    add('rule_engine_unmapped', '출처가 연결되지 않은 룰 엔진', [...new Set(cves.flatMap(c => (c.rule_engines || [])
      .filter(e => !ENGINE_SID[e]).map(e => `${c.id}:${e}`)))]);
    const ev = d.evidence;
    if (ev && ev.schema === 1) {
      const has = (k, id) => !!(ev[k] || {})[id];
      if ((ev.sources || {})['cisa-kev']) {
        add('kev_flag_without_evidence', 'KEV 등재인데 원 출처 파일에 항목 없음', cves.filter(c => c.is_kev && !has('kev', c.id)).map(c => c.id),
            '색인 시점이 달라 생길 수 있고 다음 회차에 맞춰집니다');
      }
      if ((ev.sources || {})['exploit-db']) {
        add('edb_flag_without_evidence', 'Exploit-DB 표시인데 원 출처 파일에 항목 없음',
            cves.filter(c => c.has_public_exploit && !has('edb', c.id)).map(c => c.id), '색인 시점이 달라 생길 수 있습니다');
      }
      if ((ev.sources || {}).metasploit) {
        add('msf_flag_without_evidence', 'Metasploit 표시인데 원 출처 파일에 모듈 없음',
            cves.filter(c => c.has_metasploit_module && !has('msf', c.id)).map(c => c.id), '색인 시점이 달라 생길 수 있습니다');
      }
    }
    const lc = d.lifecycle;
    if (lc && Array.isArray(lc.releases)) {
      const dateFields = ['release_date', 'support_end', 'security_support_end', 'extended_support_end', 'eol_date',
                          'latest_release_date'];
      add('lifecycle_bad_date', '수명주기 날짜 형식 오류', lc.releases.filter(r =>
        dateFields.some(k => r[k] != null && !(ISO_DATE.test(String(r[k])) && !isNaN(Date.parse(`${r[k]}T00:00:00Z`)))))
        .map(r => `${r.product_slug}|${r.cycle}`));
      add('lifecycle_bad_cycle', '수명주기 사이클 이름 오류', lc.releases.filter(r =>
        !r.cycle || !/^[a-z0-9][a-z0-9.+-]*$/i.test(String(r.cycle))).map(r => `${r.product_slug}|${r.cycle}`));
      const known = new Set(LC.STATUSES);
      add('lifecycle_bad_status', '수명주기 상태값 오류', lc.releases.filter(r => !known.has(r.lifecycle_status))
        .map(r => `${r.product_slug}|${r.cycle}`));
      const keys = new Set(), dupRel = new Set();
      for (const r of lc.releases) {
        const k = `${r.product_slug}|${r.cycle}`;
        if (keys.has(k)) dupRel.add(k);
        keys.add(k);
      }
      add('lifecycle_duplicate_release', '수명주기 릴리스 중복', [...dupRel]);
      add('lifecycle_unavailable', 'endoflife.date에 없는 추적 제품 (UNKNOWN으로 표시)',
          (lc.unavailable || []).map(u => u.slug), '데이터를 만들지 않습니다. 오류가 아니라 범위를 알려 주는 항목입니다', 'info');
    }
    if (d.kevCatalog) {
      const tracked = new Map(cves.map(c => [c.id, c]));
      add('kev_catalog_not_flagged', 'KEV 카탈로그에 있는데 추적 데이터는 KEV 아님',
          [...d.kevCatalog].filter(id => tracked.has(id) && !tracked.get(id).is_kev));
      add('kev_flag_not_in_catalog', '추적 데이터는 KEV인데 카탈로그에 없음',
          cves.filter(c => c.is_kev && !d.kevCatalog.has(c.id)).map(c => c.id));
    }
    return checks;
  }

  /* ---------- 입력 지문 (사전 계산 결과가 지금 받은 파일과 같은 판에서 나왔는지) ---------- */

  function hashString(text) {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  function fingerprint(files) {
    const f = files || {};
    const pk = (f.packages && f.packages.packages) || null;
    let pkgEntries = 0;
    if (pk) for (const m of Object.values(pk)) pkgEntries += Object.keys(m || {}).length;
    // cves 는 stats.json 만으로 확인할 수 있게 한다(export 가 total = len(cves) 로 쓴다) — 큰 파일보다 먼저 판단.
    return {
      cves: f.stats ? `${f.stats.generated_at || ''}|${(f.stats.cve && f.stats.cve.total) || 0}` : null,
      products: f.products ? String(f.products.generated_at || '') : null,
      packages: pk ? `${Object.keys(pk).length}|${pkgEntries}` : null,
      lifecycle: f.lifecycle ? `${f.lifecycle.generated_at || ''}|${(f.lifecycle.releases || []).length}` : null,
      aliases: f.aliases ? hashString(JSON.stringify(f.aliases)) : null,
    };
  }

  function sameFingerprint(a, b) {
    if (!a || !b) return false;
    return ['cves', 'products', 'packages', 'lifecycle', 'aliases'].every(k => (a[k] || null) === (b[k] || null));
  }

  return {
    EPSS_P_HIGH, EPSS_SCORE_HIGH, CVSS_CRITICAL, URL, ENGINES, ENGINE_ORDER, RULE_FAMILIES, engineInfo, RULE_LICENSE, ruleSource, ruleTerms,
    ET_FILES, ruleSid, ruleLink,
    SIGNALS, SIGNAL, SIGNAL_BY_KEY, CORRELATIONS, CORRELATION, REASON, SID, ENGINE_SID,
    scoreFacts, epssHigh, patchState, hasFix, fixedVersions, detectionEngines, ruleEngines, ruleFamilies, hasCheckTemplate,
    lifecycleFacts,
    signals, correlationsOf, reasonsOf, derive,
    SOURCE_FLAGS, sourceFlags, CONFLICTS, CONFLICT, conflictsOf, conflictQuery, sevBand,
    stateQuery, correlationQuery, parseRelease,
    MATRIX, yesQuery, trendDays, SEVERITIES, aggregate, aggregateItem, RECENT_SIGNALS, recentOf,
    qualityChecks, hashString, fingerprint, sameFingerprint,
  };
});
