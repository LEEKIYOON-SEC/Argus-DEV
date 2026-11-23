(function (root, factory) {
  'use strict';
  const node = typeof module !== 'undefined' && module.exports;
  const api = factory(node ? require('./lifecycle.js') : root.ArgusLifecycle,
                      node ? require('./context.js') : root.ArgusContext);
  root.ArgusEntities = api;
  if (node) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis, function (LC, CTX) {
  'use strict';

  /*
   * 엔티티 · 관계 — CVE 를 중심으로 묶는다.
   *   CVE ─affects──────────▶ Product ─has_lifecycle_context─▶ Cycle   (매칭 방법 · 키 · 상태 · 사유)
   *   CVE ─supported_by─────▶ Evidence ─provided_by─▶ Source
   *   CVE ─remediated_by────▶ Remediation      CVE ─scored_by─▶ Score      CVE ─described_by─▶ Text
   *   Signal(context.js 판정) ─derived_from─▶ Evidence · Score · Cycle      Correlation ─composed_of─▶ Signal
   * 판정 규칙은 context.js 하나뿐이다. 여기는 그 판정이 어떤 증거·출처에서 나왔는지를 잇는다.
   * 원 출처가 주지 않은 값(공개일 · 권고 ID 등)은 만들지 않고 null 로 둔다.
   */

  /* ---------- Source — 출처 엔티티 ----------
   * kind 'source' 는 외부 데이터 출처다. 데이터 출처 화면의 표(SOURCE_GROUPS 순서)에 이름 · 주는 정보 · 예약 주기 ·
   * 이용 조건(terms)을 싣는다 — 출처별 이용 조건은 이 표 한 곳에만 둔다(INVARIANTS §9-1).
   * terms 의 note 는 이름과 링크만으로 알 수 없는 조건만 명사로 짧게 적는다(표준 라이선스는 이름 · 링크로 충분).
   * 'derived' · 'ai' 는 증거 · 글의 출처를 잇기 위한 내부 엔티티이며 표에 싣지 않는다.
   * cadence 는 Argus 가 원본을 다시 받도록 GitHub Actions 에 걸어 둔 예약 주기다(yml cron · 캐시 수명).
   * 원본 쪽 갱신 주기가 아니고, 실제 실행은 GitHub 부하로 늦어지거나 건너뛰어 이보다 길다(INVARIANTS §2-1). */

  const URL_LICENSE = {
    cc0Kev: 'https://github.com/cisagov/kev-data/blob/develop/LICENSE',
    cc0Vulnrichment: 'https://github.com/cisagov/vulnrichment/blob/develop/LICENSE',
    drl: 'https://github.com/SigmaHQ/Detection-Rule-License',
    apache: 'https://github.com/splunk/security_content/blob/develop/LICENSE',
    nucleiMit: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md',
    etOpen: 'https://rules.emergingthreats.net/open/suricata-7.0/LICENSE',
    gpl2: 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.html',
    msf: 'https://github.com/rapid7/metasploit-framework/blob/master/LICENSE',
    poc: 'https://github.com/nomi-sec/PoC-in-GitHub/blob/master/LICENSE',
    endoflife: 'https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE',
  };

  const SOURCES = {
    'cve-record': { provides: ['severity', 'product', 'remediation', 'text'], name: 'CVE 레코드', provider: 'CVE Program · 빠진 CVSS · 영향 제품은 NVD에서 보충',
                    url: 'https://www.cve.org/', kind: 'source', role: '제목 · 설명 · 영향 제품 · CVSS · CWE · 참고 링크', cadence: '5분마다 (변경분)',
                    terms: [{ label: 'CVE 이용약관', url: 'https://www.cve.org/Legal/TermsOfUse', note: '저작권 표기 · 약관 문구 필요' },
                            { label: 'NVD 이용약관', url: 'https://nvd.nist.gov/developers/terms-of-use', note: 'NVD 고지 문구 필요' }] },
    osv: { provides: ['remediation'], name: 'OSV.dev', provider: '', url: 'https://osv.dev', kind: 'source',
           role: '패키지별 수정 버전', cadence: '매주',
           terms: [{ label: '원 DB마다 다름', url: 'https://google.github.io/osv.dev/data/',
                     note: 'GitHub Advisory Database CC-BY 4.0 · Ubuntu CC-BY-SA 4.0 등' }] },
    'ai-discovery': { provides: ['discovery'], name: 'AI 발견 기록', provider: 'Anthropic CVD 공개 원장 · CVE 레코드의 발견자 표기', url: 'https://red.anthropic.com/',
                      kind: 'source', role: 'AI가 찾아 공개한 취약점인지와 발견한 곳', cadence: '6시간마다',
                      terms: [{ label: '라이선스 표기 없음', url: '' }] },
    // CWE 번호는 CVE 레코드에 있다. 여기서는 번호의 공식 이름 · 추상화 수준만 — 예약 없이 새 판이 나오면
    // src/update_cwe.py 로 docs/js/cwe-data.js 를 다시 만든다.
    cwe: { provides: ['weakness'], name: 'CWE', provider: 'MITRE', url: 'https://cwe.mitre.org/', kind: 'source',
           role: '취약점 유형(CWE 번호)의 공식 이름 · 추상화 수준', cadence: '수동 (새 판이 나올 때)',
           terms: [{ label: 'CWE 이용약관', url: 'https://cwe.mitre.org/about/termsofuse.html', note: '저작권 표기 · 약관 문구 필요' }] },
    'cisa-kev': { provides: ['exploitation', 'ransomware', 'remediation', 'product'], name: 'CISA KEV', provider: 'CISA', url: CTX.URL.kev, kind: 'source',
                  role: '악용 확인 · 랜섬웨어 사용 · 필요 조치 · 미 연방기관 기한', cadence: '매시',
                  terms: [{ label: 'CC0 1.0', url: URL_LICENSE.cc0Kev }] },
    'vulncheck-kev': { provides: ['exploitation'], name: 'VulnCheck KEV', provider: 'VulnCheck', url: CTX.URL.vulncheck, kind: 'source',
                       role: '악용 근거 (등재 여부)', cadence: '6시간마다',
                       terms: [{ label: 'VulnCheck 이용 조건', url: 'https://docs.vulncheck.com/community/vulncheck-kev/attribution', note: '출처 표기 필수' }] },
    'cisa-adp': { provides: ['exploitation', 'automation', 'severity'], name: 'CISA SSVC (vulnrichment)', provider: 'CISA', url: 'https://github.com/cisagov/vulnrichment', kind: 'source',
                  role: 'SSVC 판정 (Exploitation · Automatable · Technical Impact) · 보충 CVSS', cadence: '5분마다 (CVE 레코드와 함께)',
                  terms: [{ label: 'CC0 1.0', url: URL_LICENSE.cc0Vulnrichment }] },
    'first-epss': { provides: ['probability'], name: 'EPSS', provider: 'FIRST.org', url: 'https://www.first.org/epss/', kind: 'source',
                    role: '30일 안에 악용될 확률 예측', cadence: '6시간마다',
                    terms: [{ label: '라이선스 표기 없음', url: 'https://www.first.org/epss/faq', note: '출처 표기 요청' }] },
    'exploit-db': { provides: ['exploit'], name: 'Exploit-DB', provider: '', url: CTX.URL.exploitdb, kind: 'source',
                    role: '공개 익스플로잇 항목', cadence: '매일',
                    terms: [{ label: '익스플로잇마다 작성자 저작', url: '' }] },
    metasploit: { provides: ['exploit'], name: 'Metasploit Framework', provider: 'Rapid7', url: CTX.URL.metasploit, kind: 'source',
                  role: '공격 모듈 이름 · 등급', cadence: '매일',
                  terms: [{ label: 'BSD-3-Clause', url: URL_LICENSE.msf }] },
    'poc-in-github': { provides: ['exploit'], name: 'PoC-in-GitHub', provider: 'nomi-sec', url: CTX.URL.poc, kind: 'source',
                       role: '공개 PoC 저장소 링크', cadence: '매시',
                       terms: [{ label: 'CC0 1.0', url: URL_LICENSE.poc }] },
    sigma: { provides: ['detection'], name: 'SigmaHQ', provider: '', url: 'https://github.com/SigmaHQ/sigma', kind: 'source',
             role: '로그 탐지 룰', cadence: '매주',
             terms: [{ label: 'DRL 1.1', url: URL_LICENSE.drl }] },
    'et-open': { provides: ['detection'], name: 'Emerging Threats Open', provider: '', url: 'https://rules.emergingthreats.net/', kind: 'source',
                 role: 'Snort · Suricata 네트워크 탐지 룰', cadence: '매주',
                 terms: [{ label: 'BSD', url: URL_LICENSE.etOpen }] },
    'snort-community': { provides: ['detection'], name: 'Snort Community Rules', provider: 'Snort', url: 'https://www.snort.org/downloads', kind: 'source',
                         role: 'Snort 네트워크 탐지 룰', cadence: '매주',
                         terms: [{ label: 'GPLv2', url: URL_LICENSE.gpl2 }] },
    splunk: { provides: ['detection'], name: 'Splunk ESCU', provider: 'Splunk security_content', url: 'https://github.com/splunk/security_content', kind: 'source',
              role: '탐지 룰', cadence: '매주',
              terms: [{ label: 'Apache-2.0', url: URL_LICENSE.apache }] },
    yara: { provides: ['detection'], name: 'YARA Forge', provider: '', url: 'https://github.com/YARAHQ/yara-forge', kind: 'source',
            role: '파일 탐지 룰', cadence: '매주',
            terms: [{ label: '룰마다 다름', url: '' }] },
    nuclei: { provides: ['detection'], name: 'nuclei-templates', provider: 'ProjectDiscovery', url: 'https://github.com/projectdiscovery/nuclei-templates', kind: 'source',
              role: '취약 여부 점검 템플릿', cadence: '매일',
              terms: [{ label: 'MIT', url: URL_LICENSE.nucleiMit }] },
    endoflife: { provides: ['lifecycle'], name: 'endoflife.date', provider: '', url: CTX.URL.endoflife, kind: 'source',
                 role: '제품 버전의 지원 단계 · EOL', cadence: '매일',
                 terms: [{ label: 'MIT', url: URL_LICENSE.endoflife }] },
    // 내부 엔티티 — 표에 싣지 않는다
    'rule-index': { provides: ['detection'], name: 'Argus 탐지 룰 색인', provider: 'Argus', url: '', kind: 'derived',
                    role: '공개 룰 저장소를 CVE ID로 색인한 결과' },
    gemma: { provides: ['text'], name: 'AI 번역', provider: '', url: '', kind: 'ai', role: '제목 한국어 번역 · 설명 요약' },
    argus: { provides: ['derived'], name: 'Argus', provider: 'Argus', url: '', kind: 'derived',
             role: 'Argus 계산 결과: 알림 등급 · 심각도 등급 · 신호 · 신호 조합 · 출처 간 차이' },
  };
  const SOURCE_ORDER = Object.keys(SOURCES);
  // 데이터 출처 표의 묶음과 순서 — 외부 출처(kind 'source')만, 빠짐없이 한 번씩.
  const SOURCE_GROUPS = [
    { label: '취약점 정보', ids: ['cve-record', 'cwe', 'osv', 'ai-discovery'] },
    { label: '악용 · 위험 신호', ids: ['cisa-kev', 'vulncheck-kev', 'cisa-adp', 'first-epss', 'exploit-db', 'metasploit', 'poc-in-github'] },
    { label: '공개 탐지 룰', ids: ['sigma', 'et-open', 'snort-community', 'splunk', 'yara', 'nuclei'] },
    { label: '제품 수명주기', ids: ['endoflife'] },
  ];
  const PROVIDES_LABEL = { exploitation: '악용 근거', exploit: '공개 익스플로잇', automation: '자동화', ransomware: '랜섬웨어',
                           detection: '탐지', remediation: '조치', lifecycle: '수명주기', severity: '심각도(CVSS)',
                           probability: '악용 확률(EPSS)', product: '영향 제품', text: '제목 · 설명', discovery: 'AI 발견',
                           weakness: '취약점 유형',
                           derived: 'Argus 계산' };

  /* ---------- Evidence Type (§6) — 출처와 섞지 않는다 ---------- */

  const EVIDENCE_TYPES = {
    exploitation: { label: '악용 근거', signal: 'EXPLOITATION_CONFIRMED', note: '실제 악용이 보고됐다는 근거' },
    exploit: { label: '공개 익스플로잇', signal: 'PUBLIC_EXPLOIT', note: '공개 익스플로잇 · PoC. 실제 공격이 있었다는 뜻은 아닙니다' },
    automation: { label: '자동화', signal: 'AUTOMATABLE', note: 'CISA SSVC 자동화 판정. 악용이 확인됐다는 뜻은 아닙니다' },
    ransomware: { label: '랜섬웨어', signal: 'RANSOMWARE', note: 'CISA KEV의 랜섬웨어 캠페인 사용 표기' },
    detection: { label: '탐지 룰', signal: 'PUBLIC_DETECTION', note: '공개된 탐지 룰. 같은 칸에 싣는 nuclei 점검 템플릿은 탐지 룰 근거로 세지 않습니다' },
    remediation: { label: '조치', signal: 'PATCH_AVAILABLE', note: '수정 버전 · 필요 조치' },
    lifecycle: { label: '수명주기', signal: 'EOL_AFFECTED', note: '영향 버전의 지원 상태. 심각도가 아닙니다' },
  };
  const GROUP_TYPE = { exploitation: 'exploitation', weaponization: 'exploit', automation: 'automation',
                       ransomware: 'ransomware', detection: 'detection', remediation: 'remediation', lifecycle: 'lifecycle' };
  const STATUS = { hit: 'present', miss: 'absent', unknown: 'unknown', info: 'info' };

  const MSF_RANK = { 0: 'manual', 100: 'low', 200: 'average', 300: 'normal', 400: 'good', 500: 'great', 600: 'excellent' };

  /* ---------- 보조 파일 풀기 (CI 가 만든 cve-evidence.json · export 가 만든 cve-facts.json) ---------- */

  function evidenceFor(file, id) {
    if (!file || file.schema !== 1) return null;
    const kev = (file.kev || {})[id];
    return {
      kev: kev ? { date_added: kev[0] || null, due: kev[1] || null,
                   action: Number.isInteger(kev[2]) ? (file.actions || [])[kev[2]] || null : null,
                   notes: kev[3] || [], name: kev[4] || '' } : null,
      edb: ((file.edb || {})[id] || []).map(e => ({ id: e[0], published: e[1] || null, added: e[2] || null,
                                                     verified: !!e[3], type: e[4] || '', platform: e[5] || '' })),
      msf: ((file.msf || {})[id] || []).map(m => ({ name: m[0], rank: m[1], rank_name: MSF_RANK[m[1]] || String(m[1]),
                                                     disclosure_date: m[2] || null, type: m[3] || '', check: !!m[4] })),
    };
  }

  const ORIGIN = ['ai', 'argus', 'source'];
  function factsFor(file, id) {
    if (!file || file.schema !== 1) return undefined;   // 파일을 아직 못 받음
    const f = (file.facts || {})[id];
    if (!f) return null;                                  // 받았지만 이 CVE 는 없음 (다음 export 에 채워짐)
    const o = Array.isArray(f.o) ? f.o : [];
    return { title: f.t || null, description: f.d || null, assigner: f.a || null,
             titleOrigin: ORIGIN.includes(o[0]) ? o[0] : null, descOrigin: ORIGIN.includes(o[1]) ? o[1] : null,
             productSources: (f.p || []).map(p => ({ vendor: p[0], product: p[1], source: p[2] })) };
  }

  /* ---------- 영향 버전 문자열 → 범위 (collector.parse_affected 형식) ---------- */

  // '… 이전' 의 상한은 레코드가 '이 버전부터 영향 없음'으로 적은 값이다 — 수정 버전일 때가 많지만 CNA 가 '수정'이라 적은 것은 아니다.
  // 경계가 버전 모양이 아니면 범위로 읽지 않고 원문 그대로 둔다 — 실측: '2.0-beta9 부터 log4j-core* 이전',
  // 'unspecified 부터 …', 'n/a', 커널 CNA 의 git 커밋 해시('63137bc5… 부터 bf84ad7c… 이전' — 숫자로 시작하는 해시도 있다).
  const versionLike = v => { const t = String(v || ''); return /^\d/.test(t) && !/^[0-9a-f]{7,40}$/i.test(t); };
  function rangesOf(versions) {
    const entries = LC.splitEntries(versions);
    if (!entries) return { ranges: [], unaffectedFrom: [], parsed: false };
    const ranges = [], unaffectedFrom = [];
    for (const e of entries) {
      const parts = e.body.split(' 부터 ');
      const upper = parts[parts.length - 1].trim();
      const lower = parts.length === 2 ? parts[0].trim() : null;
      const valid = e.kind !== 'bare' && versionLike(upper) && (lower === null || versionLike(lower));
      ranges.push({ text: e.kind === 'bare' ? e.body : `${e.body} ${e.kind}`, kind: e.kind, lower, upper, valid });
      // 영향 없음 시작 버전은 상한만 본다 — 하한이 'unspecified' 여도 상한이 버전이면 쓴다.
      if (e.kind === '이전' && versionLike(upper) && !unaffectedFrom.includes(upper)) unaffectedFrom.push(upper);
    }
    return { ranges, unaffectedFrom, parsed: true };
  }

  const normKey = (vendor, product) => `${LC.normPart(vendor)}:${LC.normPart(product)}`;
  const sameProduct = (a, b) => String(a.vendor || '').trim().toLowerCase() === String(b.vendor || '').trim().toLowerCase()
    && String(a.product || '').trim().toLowerCase() === String(b.product || '').trim().toLowerCase();

  /* ---------- CVE 하나의 엔티티 그래프 ---------- */

  // deps: context.derive 와 같음 + { match (lifecycle.js matchCve 결과), facts, evidence, files }
  function buildEntities(cve, deps) {
    const d = deps || {};
    const affected = d.affected || cve.affected || [];
    const derived = CTX.derive(cve, Object.assign({}, d, { affected }));
    const facts = d.facts;
    const ev = d.evidence || null;
    const files = d.files || {};
    const observed = { at: files.cves || null, label: 'cves.json 생성 시각' };

    /* Evidence — derive 의 출처별 행을 증거 엔티티로. 판정 상태는 그대로(hit → present …) */
    const evidence = [];
    for (const [group, type] of Object.entries(GROUP_TYPE)) {
      if (type === 'lifecycle') continue;
      for (const r of derived[group].rows) {
        const e = {
          id: `ev:${type}:${r.sid || r.source}${r.engine ? `:${r.engine}` : ''}${r.status === 'info' ? ':info' : ''}`,
          type, source: r.sid, sourceName: r.source, status: STATUS[r.status] || 'unknown', value: r.value,
          kind: r.kind, url: r.url || '', basis: r.basis || 'CVE ID', detail: r.detail || '',
          items: r.items || [], links: r.links || [], published: null, observed, extra: {},
        };
        if (r.engine) Object.assign(e.extra, { engine: r.engine, license: r.license || '', author: r.author || '',
                                                count: r.count || 1, source_name: r.source_name || '' });
        if (r.fixed) e.extra.fixed = r.fixed;
        if (r.packages) e.extra.packages = r.packages;
        evidence.push(e);
      }
    }
    // 원 출처 날짜 — 파이프라인이 받아 둔 원 파일에서 CI 가 붙인 값만 (cve-evidence.json)
    const evObserved = { at: files.evidence || null, label: 'cve-evidence.json 생성 시각' };
    for (const e of evidence) {
      if (!ev) continue;
      if (e.source === 'cisa-kev' && e.type === 'exploitation' && e.status === 'present' && ev.kev) {
        e.published = ev.kev.date_added ? { date: ev.kev.date_added, label: 'KEV 등재일' } : null;
        Object.assign(e.extra, { name: ev.kev.name, due: ev.kev.due, action: ev.kev.action, notes: ev.kev.notes });
        e.observed = evObserved;
      } else if (e.source === 'exploit-db' && e.status === 'present' && ev.edb.length) {
        const dates = ev.edb.map(x => x.published).filter(Boolean).sort();
        e.published = dates.length ? { date: dates[0], label: 'Exploit-DB 공개일 (가장 이른 항목)' } : null;
        e.extra.entries = ev.edb;
        e.observed = evObserved;
      } else if (e.source === 'metasploit' && e.status === 'present' && ev.msf.length) {
        // DisclosureDate 는 취약점 공개일이다 — 모듈이 공개된 날이 아니므로 공개일 칸에 넣지 않는다.
        e.extra.modules = ev.msf;
        e.observed = evObserved;
      }
    }

    /* Score */
    const f = CTX.scoreFacts(cve);
    const alt = cve.cvss_alt || {};
    const versions = Object.keys(alt).length ? Object.keys(alt) : (cve.cvss_version ? [cve.cvss_version] : []);
    const scores = [];
    for (const v of versions.sort().reverse()) {
      const value = Object.keys(alt).length ? Number(alt[v]) || null : f.cvss;
      scores.push({ id: `score:cvss:${v}`, kind: 'cvss', version: v, value, band: value ? CTX.sevBand(value) : null,
                    primary: v === cve.cvss_version, vector: v === cve.cvss_version ? derived.scores.cvss.vector : null });
    }
    if (!scores.length) scores.push({ id: 'score:cvss', kind: 'cvss', version: null, value: null, band: null, primary: true, vector: null });
    scores.push({ id: 'score:epss', kind: 'epss', value: f.epss, percentile: f.percentile, source: 'first-epss',
                  high: derived.states.HIGH_EPSS });

    /* Text — 화면에 나간 제목 · 설명이 원문인지 AI 생성인지.
       export 가 남긴 경로(facts.o)가 있으면 그것, 없으면 한국어 여부만 본다 — 원 출처는 영문이므로 한국어는 원문이 아니다
       (AI 번역인지 Argus 가 만든 문구인지는 그때 가를 수 없어 'generated'). */
    const koOrigin = (origin, text) => origin || (/[가-힣]/.test(String(text || '')) ? 'generated' : 'source');
    const texts = [
      { id: 'text:title', kind: 'title', lang: /[가-힣]/.test(cve.title || '') ? 'ko' : 'en', value: cve.title || '',
        origin: koOrigin(facts && facts.titleOrigin, cve.title), source: null },
      { id: 'text:description', kind: 'description', lang: /[가-힣]/.test(cve.description || '') ? 'ko' : 'en',
        value: cve.description || '', origin: koOrigin(facts && facts.descOrigin, cve.description), source: null },
    ];
    for (const t of texts) t.source = t.origin === 'ai' ? 'gemma' : t.origin === 'argus' ? 'argus' : t.origin === 'source' ? 'cve-record' : null;
    const ORIGIN_TEXT = { ai: 'AI 작성 (Gemma 번역 · 요약)', argus: 'Argus가 만든 문구', source: '원문 (CVE 레코드)',
                          generated: '한국어로 만든 글 (AI 번역 또는 Argus 문구, 원문 아님)' };
    for (const t of texts) t.originLabel = ORIGIN_TEXT[t.origin] || '';
    if (facts && facts.title) texts.push({ id: 'text:title:original', kind: 'title', lang: 'en', value: facts.title, origin: 'source', source: 'cve-record' });
    if (facts && facts.description) texts.push({ id: 'text:description:original', kind: 'description', lang: 'en', value: facts.description, origin: 'source', source: 'cve-record' });

    /* Product → Cycle — 영향 제품 항목마다 수명주기 매칭 결과를 붙인다 */
    const lcProducts = d.products || {};
    const lifecycleOf = r => {
      if (!d.lifecycle || !d.match) return { status: 'no_data', reason: 'lifecycle_unloaded' };
      if (r == null) return { status: 'untracked', reason: 'untracked' };
      if (r.denied) return { status: 'denied', via: 'override', method: LC.VIA.override, key: r.key, explicit: true };
      const meta = lcProducts[r.slug] || {};
      const cycles = (r.cycles || []).map(rel => ({
        id: `cycle:${r.slug}|${rel.cycle}`, slug: r.slug, cycle: rel.cycle, label: rel.cycle_label || rel.cycle,
        status: LC.statusOf(rel, meta, d.today), eol_date: rel.eol_date || null, support_end: rel.support_end || null,
        security_support_end: rel.security_support_end || null, extended_support_end: rel.extended_support_end || null,
        latest_version: rel.latest_version || null, fetched_at: rel.fetched_at || meta.fetched_at || null,
        url: meta.source_url || CTX.URL.endoflife }));
      return { status: cycles.length ? 'matched' : 'product_only', slug: r.slug, product: meta.label || r.slug,
               via: r.via, method: LC.VIA[r.via] || r.via, key: r.key, basis: r.basis || null,
               explicit: r.via === 'override', reason: cycles.length ? null : r.reason || null, cycles };
    };
    const matchItems = (d.match && d.match.items) || [];
    const products = affected.map((a, i) => {
      const rg = rangesOf(a.versions);
      const src = facts && (facts.productSources || []).find(p => sameProduct(p, a));
      return { id: `prod:${i}`, kind: 'affected', vendor: a.vendor || '', product: a.product || '', versions: a.versions || '',
               key: normKey(a.vendor, a.product), source: src ? src.source : null,
               sourceNote: src ? `${src.source} 표기로 채운 제품` : (facts ? 'CVE 레코드 (옛 레코드는 NVD CPE로 보충했을 수 있음)' : ''),
               ranges: rg.ranges, unaffectedFrom: rg.unaffectedFrom, rangesParsed: rg.parsed, lifecycle: lifecycleOf(matchItems[i]) };
    });
    // OSV 패키지(PURL)로 이어진 릴리스 — 영향 제품 항목이 아니라 패키지에서 나온 연결이라 따로 둔다.
    ((d.match && d.match.packages) || []).forEach((r, i) => {
      if (!r) return;
      products.push({ id: `pkg:${i}`, kind: 'package', vendor: '', product: r.key || '', versions: '', key: r.key || '',
                      source: 'osv', sourceNote: 'OSV 패키지(PURL)의 수정 버전으로 릴리스를 연결', ranges: [],
                      unaffectedFrom: [], rangesParsed: false, lifecycle: lifecycleOf(r) });
    });

    /* Remediation */
    const remediation = [];
    for (const fx of derived.remediation.fixed || []) {
      remediation.push({ id: `rem:osv:${fx.ecosystem}:${fx.package}`, kind: 'fixed_version', source: 'osv',
                         package: fx.package, ecosystem: fx.ecosystem, versions: fx.versions });
    }
    for (const p of products) {
      if (p.unaffectedFrom.length) {
        remediation.push({ id: `rem:record:${p.id}`, kind: 'unaffected_from', source: 'cve-record',
                           product: [p.vendor, p.product].filter(Boolean).join(' '), versions: p.unaffectedFrom });
      }
    }
    if (cve.is_kev && (cve.kev_due_date || (ev && ev.kev))) {
      remediation.push({ id: 'rem:kev', kind: 'required_action', source: 'cisa-kev',
                         due: cve.kev_due_date || (ev && ev.kev && ev.kev.due) || null,
                         action: (ev && ev.kev && ev.kev.action) || null, notes: (ev && ev.kev && ev.kev.notes) || [] });
    }
    const references = [...new Set((cve.references || []).filter(Boolean))].map((url, i) => ({
      id: `ref:${i}`, kind: 'reference', source: 'cve-record', url }));

    /* Signal ← Evidence / Score / Cycle — 판정은 context.js, 여기는 근거 연결만 */
    const present = type => evidence.filter(e => e.type === type && e.status === 'present').map(e => e.id);
    const eolCycles = products.flatMap(p => (p.lifecycle.cycles || []).filter(c => c.status === 'EOL').map(c => c.id));
    const primary = scores.find(s => s.kind === 'cvss' && s.primary) || scores[0];
    const support = {
      EXPLOITATION_CONFIRMED: present('exploitation'),
      CISA_KEV: evidence.filter(e => e.source === 'cisa-kev' && e.type === 'exploitation' && e.status === 'present').map(e => e.id),
      PUBLIC_EXPLOIT: present('exploit'),
      AUTOMATABLE: present('automation'),
      RANSOMWARE: present('ransomware'),
      EOL_AFFECTED: [...new Set(eolCycles)],
      PATCH_AVAILABLE: remediation.filter(r => r.kind === 'fixed_version').map(r => r.id),
      // 점검 템플릿(nuclei)은 탐지 룰 칸에 함께 싣지만 탐지 룰의 근거는 아니다.
      PUBLIC_DETECTION: evidence.filter(e => e.type === 'detection' && e.status === 'present' && e.kind !== 'check').map(e => e.id),
      HIGH_EPSS: ['score:epss'],
      CRITICAL_CVSS: [primary.id],
    };
    const signals = {};
    for (const s of CTX.SIGNALS) {
      signals[s.code] = { code: s.code, state: derived.states[s.code], reasons: derived.reasons[s.code] || [],
                          supportedBy: derived.states[s.code] === 'yes' ? support[s.code] : [] };
    }
    const correlations = derived.correlations.map(code => {
      const c = CTX.CORRELATION[code];
      return { code, label: c.label, short: c.short, query: c.query,
               parts: c.parts.map(p => {
                 const neg = p[0] === '!';
                 const sc = neg ? p.slice(1) : p;
                 return { code: sc, negated: neg, state: derived.states[sc], supportedBy: neg ? [] : signals[sc].supportedBy };
               }) };
    });

    /* Conflict — 어느 쪽도 지우지 않는다 */
    const conflicts = CTX.conflictsOf(cve).map(code => {
      const c = CTX.CONFLICT[code];
      let sides = [];
      if (code === 'EXPLOITATION_SSVC' || code === 'EXPLOIT_SSVC') {
        const type = code === 'EXPLOITATION_SSVC' ? 'exploitation' : 'exploit';
        sides = evidence.filter(e => e.type === type && e.status === 'present' && e.source !== 'cisa-adp')
          .map(e => ({ source: e.source, value: `${e.sourceName} ${e.value}`, evidence: e.id }))
          .concat([{ source: 'cisa-adp', value: `CISA SSVC Exploitation: ${cve.ssvc_exploitation}`, evidence: null }]);
      } else if (code === 'CVSS_VERSIONS') {
        sides = scores.filter(s => s.kind === 'cvss' && s.value).map(s => ({ source: null, value: `CVSS ${s.version} ${s.value} (${s.band})`,
                                                                           evidence: s.id, primary: s.primary }));
      }
      for (const s of sides) {
        const e = evidence.find(x => x.id === s.evidence);
        if (e) e.conflict = code;
      }
      return { code, subject: c.subject, label: c.label, rule: c.rule, sides };
    });

    return {
      id: cve.id,
      cve: { id: cve.id, published: cve.published || null, assigner: facts ? facts.assigner : null, cwe: cve.cwe || [],
             severity: cve.severity || 'None', tier: cve.tier || null, argusDate: cve.date || null, updated: cve.updated || null },
      texts, scores, products, evidence, remediation, references, signals, correlations, conflicts,
      lifecycle: derived.lifecycle,
      discovery: derived.discovery,
      analysis: cve.analysis || null,
      derived,
    };
  }

  return {
    SOURCES, SOURCE_ORDER, SOURCE_GROUPS, PROVIDES_LABEL, EVIDENCE_TYPES, MSF_RANK,
    evidenceFor, factsFor, rangesOf, normKey, buildEntities,
  };
});
