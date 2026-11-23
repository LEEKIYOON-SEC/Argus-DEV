'use strict';
// 파생 계층(docs/js/context.js) — tri-state 판정, 근거 행렬, 상관, 집계, 품질 점검, CI 사전 계산.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const LC = require('../docs/js/lifecycle.js');
const CTX = require('../docs/js/context.js');
const { build, productDecoder } = require('../src/build_context.js');

const fx = name => require(path.join(__dirname, 'fixtures', name));
const TODAY = '2026-09-27';
const LCDATA = fx('lifecycle_sample.json');
const ALIASES = require('../data/lifecycle_aliases.json');

// 필드를 채우지 않은 최소 행 — 판정에 쓰는 필드만 덮어쓴다.
const row = over => Object.assign({
  id: 'CVE-2026-9000', cvss: 7.5, cvss_version: '3.1', epss: 0.02, epss_percentile: 0.5,
  is_kev: false, is_vulncheck_kev: false, is_kev_ransomware: false, kev_due_date: '',
  ssvc_exploitation: null, ssvc_automatable: null, ssvc_technical_impact: null,
  has_public_exploit: false, has_metasploit_module: false, metasploit_modules: [], has_poc: false, poc_urls: [],
  has_nuclei_template: false, rule_engines: [], has_official_rules: false, affected: [], references: [],
}, over);

const states = (cve, deps) => CTX.signals(cve, Object.assign({ today: TODAY }, deps)).states;

test('악용 근거 — CISA KEV · VulnCheck · SSVC active 중 하나면 yes, CISA KEV 는 따로 판정', () => {
  assert.equal(states(row({ is_kev: true })).EXPLOITATION_CONFIRMED, 'yes');
  assert.equal(states(row({ is_kev: true })).CISA_KEV, 'yes');
  assert.equal(states(row({ is_vulncheck_kev: true })).EXPLOITATION_CONFIRMED, 'yes');
  assert.equal(states(row({ is_vulncheck_kev: true })).CISA_KEV, 'no', 'VulnCheck 만으로 CISA KEV 가 되지 않는다');
  assert.equal(states(row({ ssvc_exploitation: 'active' })).EXPLOITATION_CONFIRMED, 'yes');
  assert.equal(states(row({ ssvc_exploitation: 'poc' })).EXPLOITATION_CONFIRMED, 'no', 'SSVC poc 는 악용 근거가 아니다');
  assert.equal(states(row()).EXPLOITATION_CONFIRMED, 'no');
});

test('공개 exploit — Exploit-DB · Metasploit · PoC 만 센다 (nuclei · SSVC poc 는 아님)', () => {
  for (const k of ['has_public_exploit', 'has_metasploit_module', 'has_poc']) {
    assert.equal(states(row({ [k]: true })).PUBLIC_EXPLOIT, 'yes', k);
  }
  assert.equal(states(row({ has_nuclei_template: true })).PUBLIC_EXPLOIT, 'no');
  assert.equal(states(row({ ssvc_exploitation: 'poc' })).PUBLIC_EXPLOIT, 'no');
});

test('false 와 unknown 을 가른다 — 자동화 · 랜섬웨어 · EPSS · CVSS', () => {
  assert.equal(states(row({ ssvc_automatable: 'yes' })).AUTOMATABLE, 'yes');
  assert.equal(states(row({ ssvc_automatable: 'no' })).AUTOMATABLE, 'no');
  assert.equal(states(row()).AUTOMATABLE, 'unknown', 'SSVC 판정이 없으면 no 가 아니다');
  assert.equal(states(row({ is_kev: true, is_kev_ransomware: true })).RANSOMWARE, 'yes');
  assert.equal(states(row({ is_kev: true })).RANSOMWARE, 'unknown', 'KEV 의 Unknown 은 "아님"이 아니다');
  assert.equal(states(row()).RANSOMWARE, 'unknown');
  assert.equal(states(row({ epss: 0, epss_percentile: 0 })).HIGH_EPSS, 'unknown', 'EPSS 0 은 미채점');
  assert.equal(states(row({ epss: 0.3, epss_percentile: 0.95 })).HIGH_EPSS, 'yes', '백분위 95 이상');
  assert.equal(states(row({ epss: 0.3, epss_percentile: 0.94 })).HIGH_EPSS, 'no');
  assert.equal(states(row({ epss: 0.1, epss_percentile: 0 })).HIGH_EPSS, 'yes', '백분위가 없으면 확률 9.3% 기준');
  assert.equal(states(row({ epss: 0.05, epss_percentile: 0 })).HIGH_EPSS, 'no');
  assert.equal(states(row({ cvss: 9.0 })).CRITICAL_CVSS, 'yes');
  assert.equal(states(row({ cvss: 8.9 })).CRITICAL_CVSS, 'no');
  assert.equal(states(row({ cvss: 0, cvss_version: '' })).CRITICAL_CVSS, 'unknown', '0 점은 점수 없음');
});

test('수정 버전 — OSV 수정 버전 yes · 기록은 있는데 수정 없음 no · 기록 없음 unknown', () => {
  assert.equal(states(row(), { packages: { apache2: { 'Debian:12': ['2.4.62-1'] } } }).PATCH_AVAILABLE, 'yes');
  assert.equal(states(row(), { packages: { php: { 'Ubuntu:22.04:LTS': [] } } }).PATCH_AVAILABLE, 'no');
  assert.equal(states(row(), { packages: { linux: {} } }).PATCH_AVAILABLE, 'no');
  assert.equal(states(row(), { packages: undefined }).PATCH_AVAILABLE, 'unknown');
  assert.equal(states(row(), { packages: {} }).PATCH_AVAILABLE, 'unknown');
});

test('공개 탐지 — Sigma · Snort · Suricata · Splunk · YARA 만 탐지 룰, nuclei 점검 템플릿은 따로', () => {
  assert.equal(states(row({ rule_engines: ['suricata7'] })).PUBLIC_DETECTION, 'yes');
  for (const e of ['sigma', 'snort2', 'snort3', 'suricata5', 'splunk', 'yara']) {
    assert.equal(states(row({ rule_engines: [e] })).PUBLIC_DETECTION, 'yes', e);
  }
  assert.equal(states(row({ has_nuclei_template: true })).PUBLIC_DETECTION, 'no', 'nuclei 색인만 — 점검 템플릿은 탐지 룰이 아니다');
  assert.equal(states(row({ rule_engines: ['nuclei'], has_official_rules: true })).PUBLIC_DETECTION, 'no',
               '룰 색인의 nuclei 만 (공식 룰 표시도 nuclei 때문)');
  assert.equal(states(row({ rule_engines: ['nuclei', 'sigma'], has_official_rules: true })).PUBLIC_DETECTION, 'yes');
  assert.equal(states(row({ has_official_rules: true })).PUBLIC_DETECTION, 'unknown', '어떤 룰인지 남지 않았으면 단정하지 않는다');
  assert.deepEqual(CTX.reasonsOf(row({ has_official_rules: true }), states(row({ has_official_rules: true })), { reasons: [] })
    .PUBLIC_DETECTION, ['rules_unlisted']);
  assert.equal(states(row()).PUBLIC_DETECTION, 'no');
  // 엔진 계열 · 점검 템플릿
  const both = row({ rule_engines: ['suricata7', 'snort2', 'nuclei', 'yara', 'suricata5'] });
  assert.deepEqual(CTX.ruleFamilies(both), ['snort', 'suricata', 'yara'], '계열 순서는 RULE_FAMILIES 순서, 판은 하나로');
  assert.deepEqual(CTX.ruleEngines(both), ['suricata7', 'snort2', 'yara', 'suricata5'], 'nuclei 는 탐지 룰 엔진이 아니다');
  assert.equal(CTX.hasCheckTemplate(both), true);
  assert.equal(CTX.hasCheckTemplate(row({ has_nuclei_template: true })), true, 'nuclei 색인만 있어도');
  assert.equal(CTX.hasCheckTemplate(row({ rule_engines: ['sigma'] })), false);
  assert.deepEqual(CTX.RULE_FAMILIES.map(f => f.key), ['snort', 'suricata', 'sigma', 'yara', 'splunk']);
  assert.equal(CTX.sourceFlags(row({ rule_engines: ['nuclei'] })).nuclei, true, '출처 화면 nuclei 건수 = has:nuclei');
  assert.equal('rules' in CTX.sourceFlags(row()), false, '쓰지 않던 rules 값은 지웠다');
});

test('탐지 룰 라이선스 — 출처로 표기하고 옛 표기를 바로잡으며, 라이선스가 없는 YARA 는 링크만', () => {
  // 옛 색인은 ET Open 을 MIT 로, Snort Community 를 'MIT / GPLv2' 로 적었다 — 출처(source)로 바로잡는다.
  const et = CTX.ruleTerms({ engine: 'snort2', source: 'Snort 2.9 ET Open', license: 'MIT / GPLv2(레거시 SID 1–3464)', code: 'alert a' });
  assert.deepEqual([et.sid, et.license, et.body], ['et-open', 'BSD', true]);
  assert.equal(et.licenseUrl, 'https://rules.emergingthreats.net/open/suricata-7.0/LICENSE');
  assert.match(et.holder, /Emerging Threats/);
  assert.equal(CTX.ruleTerms({ engine: 'suricata7', source: 'Suricata 7 ET Open', license: 'MIT' }).license, 'BSD');
  const community = CTX.ruleTerms({ engine: 'snort3', source: 'Snort 3 Community', license: 'MIT / GPLv2(레거시 SID 1–3464)' });
  assert.deepEqual([community.sid, community.license], ['snort-community', 'GPLv2']);
  assert.equal(community.licenseUrl, 'https://www.gnu.org/licenses/old-licenses/gpl-2.0.html');
  assert.equal(CTX.ruleTerms({ engine: 'sigma' }).licenseUrl, 'https://github.com/SigmaHQ/Detection-Rule-License');
  assert.equal(CTX.ruleTerms({ engine: 'splunk' }).license, 'Apache-2.0');
  assert.equal(CTX.ruleTerms({ engine: 'nuclei', code: 'x' }).body, false, '점검 템플릿은 늘 링크만');
  // YARA — export 가 적은 저장소 라이선스를 쓰고, 옛 '룰별 상이'는 이름 없이 원 저장소 LICENSE 링크만
  const yara = CTX.ruleTerms({ engine: 'yara', license: 'DRL 1.1', license_url: 'https://github.com/Neo23x0/signature-base/blob/x/LICENSE', code: 'rule a {}' });
  assert.deepEqual([yara.license, yara.body], ['DRL 1.1', true]);
  const legacy = CTX.ruleTerms({ engine: 'yara', license: '룰별 상이', license_url: 'https://github.com/elceef/yara-rulz/blob/x/LICENSE', code: 'rule a {}' });
  assert.deepEqual([legacy.license, legacy.licenseUrl !== '', legacy.body], ['', true, true]);
  const none = CTX.ruleTerms({ engine: 'yara', license: '룰별 상이', license_url: 'N/A', code: 'rule a {}' });
  assert.deepEqual([none.license, none.licenseUrl, none.body], ['', '', false], 'LICENSE 가 없는 저장소의 룰은 본문을 싣지 않는다');
  assert.equal(CTX.ruleTerms({ engine: 'yara', link_only: true, license_url: 'https://github.com/a/b/blob/x/LICENSE', code: 'x' }).body, false);
  // BSD · MIT 저장소의 저작권 문구는 export 가 적은 그대로(옛 데이터에는 없다)
  const bsd = CTX.ruleTerms({ engine: 'yara', license: 'BSD-2-Clause', holder: 'Copyright 2022 by Volexity, Inc.',
                              license_url: 'https://github.com/volexity/threat-intel/blob/x/LICENSE.txt', code: 'rule v {}' });
  assert.deepEqual([bsd.license, bsd.holder, bsd.body], ['BSD-2-Clause', 'Copyright 2022 by Volexity, Inc.', true]);
  assert.equal(legacy.holder, '');
});

test('탐지 근거 행 — 같은 엔진이라도 룰이 온 곳이 다르면 행을 나누고, 라이선스는 출처 기준', () => {
  const cve = row({ id: 'CVE-2019-0708', rule_engines: ['snort2'], rules: { network: [
    { engine: 'snort2', source: 'Snort 2.9 ET Open', license: 'MIT', code: 'alert a' },
    { engine: 'snort2', source: 'Snort 2.9 Community', license: 'MIT / GPLv2(레거시 SID 1–3464)', code: 'alert b' },
    { engine: 'snort2', source: 'Snort 2.9 ET Open', license: 'MIT', code: 'alert c' }] } });
  const rows = CTX.derive(cve, { today: TODAY }).detection.rows;
  assert.deepEqual(rows.map(r => [r.sid, r.license, r.count]), [['et-open', 'BSD', 2], ['snort-community', 'GPLv2', 1]]);
});

test('룰 원문 링크 — 색인 url, ET Open 은 분류 파일 + SID 위치, Snort Community 는 snort.org 룰 문서, 모르는 분류는 링크 없음', () => {
  const et = 'alert http any any -> $HOME_NET any (msg:"ET EXPLOIT Acme RCE (CVE-2026-0001)"; sid:2069042; rev:2;)';
  const link = r => CTX.ruleLink(r, { _nuclei_url: 'https://github.com/pd/t.yaml' });
  assert.deepEqual(CTX.ruleSid({ code: et }), { sid: '2069042', gid: '1' });
  assert.deepEqual(CTX.ruleSid({ code: 'alert tcp (gid:3; sid:21375;)' }), { sid: '21375', gid: '3' });
  assert.equal(CTX.ruleSid({ code: 'alert x' }), null);
  const s7 = link({ engine: 'suricata7', source: 'Suricata 7 ET Open', code: et, url: '' });
  assert.equal(s7.url, 'https://rules.emergingthreats.net/open/suricata-7.0/rules/emerging-exploit.rules#:~:text=sid:2069042;');
  assert.deepEqual([s7.text, s7.size, s7.file], ['원문 파일', 1.5, 'emerging-exploit.rules']);
  assert.equal(link({ engine: 'snort2', source: 'Snort 2.9 ET Open', code: et }).url,
               'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-exploit.rules#:~:text=sid:2069042;', 'Snort 2.9 판 디렉터리');
  assert.equal(link({ engine: 'suricata5', source: 'Suricata 5 ET Open', code: et.replace('ET EXPLOIT', 'ET TROJAN') }), null,
               'TROJAN 분류 파일은 Snort 2.9 판에만 있다 — 없는 파일로 보내지 않는다');
  assert.equal(link({ engine: 'suricata7', source: 'Suricata 7 ET Open', code: et.replace('ET EXPLOIT', 'ET CONSTRUCTOR') }), null);
  assert.equal(link({ engine: 'suricata7', source: 'Suricata 7 ET Open', code: 'alert x' }), null, 'msg 에 분류가 없으면 링크 없음');
  const snort = link({ engine: 'snort3', source: 'Snort 3 Community', code: 'alert http (msg:"SERVER-WEBAPP x"; sid:300052; rev:1;)' });
  assert.deepEqual([snort.url, snort.text, snort.size], ['https://www.snort.org/rule-docs/1-300052', '룰 설명', null]);
  assert.equal(link({ engine: 'snort2', source: 'Snort 2.9 Community', code: 'alert x' }), null, 'SID 가 없으면 문서를 찾을 수 없다');
  assert.equal(link({ engine: 'snort2', source: 'Snort 2.9 ET Open', code: et, url: 'https://example.org/r' }).url, 'https://example.org/r', '색인이 url 을 주면 그것을 쓴다');
  assert.equal(link({ engine: 'sigma', url: 'https://github.com/SigmaHQ/x.yml' }).url, 'https://github.com/SigmaHQ/x.yml');
  assert.equal(link({ engine: 'sigma', url: 'javascript:alert(1)' }), null, 'http(s) 가 아니면 링크 없음');
  assert.equal(link({ engine: 'nuclei', url: '' }).url, 'https://github.com/pd/t.yaml', 'nuclei 는 CVE 의 템플릿 주소');
  // 근거 행(출처별 근거 표의 링크)도 같은 링크 — 예전에는 네트워크 룰 행에 링크가 없었다
  const cve = row({ id: 'CVE-2026-0001', rule_engines: ['suricata7', 'snort2'], rules: { network: [
    { engine: 'suricata7', source: 'Suricata 7 ET Open', code: et, url: '' },
    { engine: 'snort2', source: 'Snort 2.9 Community', code: 'alert tcp (msg:"SERVER-WEBAPP y"; sid:59927; rev:2;)', url: '' }] } });
  const rows = CTX.derive(cve, { today: TODAY }).detection.rows;
  assert.deepEqual(rows.map(r => [r.engine, r.url]), [['suricata7', s7.url], ['snort2', 'https://www.snort.org/rule-docs/1-59927']]);
  // 분류 표 — 데이터에 나온 분류가 판마다 있는지(2026-09-30 배포본 실측)
  for (const [dir, cats] of Object.entries({ 'snort-2.9.0': ['web_specific_apps', 'exploit', 'web_server', 'trojan', 'info', 'current_events'],
                                             'suricata-7.0': ['web_specific_apps', 'exploit', 'malware', 'hunting', 'coinminer', 'exploit_kit'] })) {
    for (const c of cats) assert.ok(c in CTX.ET_FILES[dir], `${dir} ${c}`);
  }
  assert.equal(CTX.ET_FILES['suricata-5.0'], CTX.ET_FILES['suricata-7.0'], 'Suricata 5 · 7 판은 분류 파일이 같다');
});

test('EOL 영향 — 하나라도 EOL 이면 yes, 모든 제품이 확인돼야 no, 나머지는 unknown(사유 포함)', () => {
  const m = LC.createMatcher(LCDATA, ALIASES);
  const eol = { vendor: 'Microsoft', product: 'Windows 7 Service Pack 1', versions: '6.1.0 이전' };
  // 하한이 열린 '1.30.0 이전' 은 그보다 오래된(EOL) 사이클까지 잇는다 — 범위를 닫아 ACTIVE 하나만 잇는다.
  const active = { vendor: 'F5', product: 'NGINX Open Source', versions: '1.30.0 부터 1.30.2 이전' };
  const acme = { vendor: 'Acme', product: 'Widget', versions: '1.0' };
  const run = aff => {
    const lc = m.forCve(aff, null);
    return CTX.signals(row(), { lifecycle: lc, products: LCDATA.products, today: TODAY, affectedCount: aff.length });
  };
  assert.equal(run([eol]).states.EOL_AFFECTED, 'yes');
  assert.equal(run([eol, acme]).states.EOL_AFFECTED, 'yes', 'EOL 이 하나라도 확인되면 나머지와 무관하게 yes');
  const onlyActive = run([active]);
  assert.equal(onlyActive.states.EOL_AFFECTED, 'no');
  const mixed = run([active, acme]);
  assert.equal(mixed.states.EOL_AFFECTED, 'unknown', '추적 밖 제품이 섞이면 no 라고 말할 수 없다');
  assert.deepEqual(mixed.lifecycle.reasons, ['untracked']);
  // 같은 제품의 다른 항목이 버전을 못 읽으면(실데이터 CVE-2019-10098 형태) 그 항목이 EOL 사이클일 수 있다.
  const partial = run([active, { vendor: 'F5', product: 'NGINX Open Source', versions: '정보 없음' }]);
  assert.equal(partial.states.EOL_AFFECTED, 'unknown', '사이클 미상 항목이 남아 있으면 no 라고 말할 수 없다');
  assert.deepEqual(partial.lifecycle.reasons, ['unresolved']);
  assert.deepEqual(run([]).lifecycle.reasons, ['no_affected']);
  const noData = CTX.signals(row(), { lifecycle: null, today: TODAY, affectedCount: 1 });
  assert.equal(noData.states.EOL_AFFECTED, 'unknown');
  assert.deepEqual(noData.lifecycle.reasons, ['lifecycle_unloaded']);
});

test('상관 — 두 사실이 모두 yes 일 때만, "!" 는 명시적 no 만 (unknown 은 해당 없음)', () => {
  const s = Object.fromEntries(CTX.SIGNALS.map(x => [x.code, 'no']));
  assert.deepEqual(CTX.correlationsOf(s), []);
  const kevEol = Object.assign({}, s, { CISA_KEV: 'yes', EOL_AFFECTED: 'yes', EXPLOITATION_CONFIRMED: 'yes' });
  assert.ok(CTX.correlationsOf(kevEol).includes('KEV_EOL'));
  const exploit = Object.assign({}, s, { PUBLIC_EXPLOIT: 'yes', PATCH_AVAILABLE: 'no' });
  assert.ok(CTX.correlationsOf(exploit).includes('EXPLOIT_NO_FIX'));
  const exploitUnknownPatch = Object.assign({}, s, { PUBLIC_EXPLOIT: 'yes', PATCH_AVAILABLE: 'unknown' });
  assert.ok(!CTX.correlationsOf(exploitUnknownPatch).includes('EXPLOIT_NO_FIX'), 'OSV 기록이 없으면 "패치 없음"이 아니다');
  const eolUnknown = Object.assign({}, s, { CISA_KEV: 'yes', EOL_AFFECTED: 'unknown' });
  assert.ok(!CTX.correlationsOf(eolUnknown).includes('KEV_EOL'));
  for (const c of CTX.CORRELATIONS) {
    for (const p of c.parts) assert.ok(CTX.SIGNAL[p.replace('!', '')], `${c.code}: 정의되지 않은 신호 ${p}`);
    assert.ok(c.query && c.label, `${c.code}: 검색어·설명 필요`);
  }
});

test('근거 행렬 — 출처마다 hit/miss/unknown, 링크, AI 분석은 섞이지 않는다', () => {
  const cve = row({
    id: 'CVE-2026-0001', is_kev: true, kev_due_date: '2026-10-01', is_kev_ransomware: true,
    has_metasploit_module: true, metasploit_modules: ['exploit/windows/x'], has_poc: true,
    poc_urls: ['https://github.com/a/b', 'https://github.com/a/b'], ssvc_exploitation: 'poc',
    rule_engines: ['sigma', 'nuclei'], has_official_rules: true, _nuclei_url: 'https://github.com/pd/t.yaml',
    rules: { sigma: { source: 'SigmaHQ', url: 'https://github.com/SigmaHQ/x.yml', license: 'DRL 1.1', author: 'A' } },
    analysis: { root_cause: 'AI-GENERATED-TEXT', mitigation: ['AI-STEP'] },
  });
  const ctx = CTX.derive(cve, { today: TODAY, packages: { openssl: { 'Debian:12': ['3.0.1'] } } });
  const kev = ctx.exploitation.rows.find(r => r.source === 'CISA KEV');
  assert.equal(kev.status, 'hit');
  assert.match(kev.detail, /2026-10-01/);
  assert.equal(ctx.exploitation.rows.find(r => r.source === 'VulnCheck KEV').status, 'miss');
  assert.equal(ctx.exploitation.rows.find(r => r.source === 'CISA SSVC').status, 'miss');
  const poc = ctx.weaponization.rows.find(r => r.source === 'PoC-in-GitHub');
  assert.deepEqual(poc.links, ['https://github.com/a/b'], '중복 링크는 한 번만');
  assert.equal(ctx.weaponization.rows.find(r => r.source === 'CISA SSVC').status, 'info');
  assert.equal(ctx.ransomware.state, 'yes');
  const sigma = ctx.detection.rows.find(r => r.engine === 'sigma');
  assert.equal(sigma.license, 'DRL 1.1');
  assert.equal(ctx.detection.rows.find(r => r.engine === 'nuclei').kind, 'check');
  assert.equal(ctx.remediation.state, 'yes');
  assert.equal(ctx.remediation.rows.find(r => r.source === 'OSV').url, 'https://osv.dev/list?q=CVE-2026-0001');
  assert.ok(ctx.remediation.rows.some(r => r.source === 'CISA KEV' && r.status === 'info'), 'KEV 조치기한은 참고 행');
  assert.equal(ctx.scores.epss.source.url, 'https://api.first.org/data/v1/epss?cve=CVE-2026-0001');
  const json = JSON.stringify(ctx);
  assert.doesNotMatch(json, /AI-GENERATED-TEXT|AI-STEP/, 'AI 분석은 파생 판단에 들어가지 않는다');
  for (const g of ['exploitation', 'weaponization', 'automation', 'ransomware', 'detection', 'remediation']) {
    for (const r of ctx[g].rows) {
      assert.ok(['hit', 'miss', 'unknown', 'info'].includes(r.status), `${g}.${r.source}`);
      assert.ok(r.basis, `${g}.${r.source}: 연결 근거(basis) 필요`);
    }
  }
});

test('수명주기 근거 — 릴리스별 상태·EOL 날짜·연결 방법·수집 시각, 명시 매핑과 자동 매핑 구분', () => {
  const m = LC.createMatcher(LCDATA, ALIASES);
  const aff = [{ vendor: 'F5', product: 'NGINX Open Source', versions: '1.24.0 부터 1.24.3 이전' },
               { vendor: 'Microsoft', product: 'Windows 7 Service Pack 1', versions: '6.1.0 이전' }];
  const ctx = CTX.derive(row({ affected: aff }), { today: TODAY, lifecycle: m.forCve(aff, null),
                                                   products: LCDATA.products, affected: aff });
  const nginx = ctx.lifecycle.rows.find(r => r.slug === 'nginx');
  assert.equal(nginx.via, 'override');
  assert.equal(nginx.match, 'explicit');
  const win = ctx.lifecycle.rows.find(r => r.slug === 'windows');
  assert.equal(win.status, 'hit');
  assert.equal(win.value, 'EOL');
  assert.equal(win.match, 'automatic');
  assert.ok(win.fetched_at, '수집 시각');
  assert.ok(win.url.startsWith('https://endoflife.date/'));
});

test('집계 — 신호별 yes/no/unknown · 상관 · 릴리스별 위협 관측', () => {
  const items = [
    { id: 'a', states: Object.assign(Object.fromEntries(CTX.SIGNALS.map(s => [s.code, 'no'])),
                                     { CISA_KEV: 'yes', EOL_AFFECTED: 'yes', EXPLOITATION_CONFIRMED: 'yes' }),
      correlations: ['KEV_EOL'], releases: ['windows|7-sp1'] },
    { id: 'b', states: Object.fromEntries(CTX.SIGNALS.map(s => [s.code, 'unknown'])), correlations: [],
      releases: [], productOnly: true },
  ];
  const agg = CTX.aggregate(items);
  assert.equal(agg.total, 2);
  assert.deepEqual(agg.signals.CISA_KEV, { yes: 1, no: 0, unknown: 1 });
  assert.equal(agg.correlations.KEV_EOL, 1);
  assert.equal(agg.releases['windows|7-sp1'].kev, 1);
  assert.equal(agg.releases['windows|7-sp1'].exploited, 1);
  assert.deepEqual(agg.lifecycle, { mapped: 2, cycle_level: 1, product_only: 1 });
});

test('데이터 품질 — 잘못된 ID · 중복 · KEV 불일치 · 링크 중복 · 수명주기 형식', () => {
  const cves = [
    row({ id: 'CVE-2026-1' }), row({ id: 'CVE-2026-9001' }), row({ id: 'CVE-2026-9001' }),
    row({ id: 'CVE-2026-9002', is_kev_ransomware: true }), row({ id: 'CVE-2026-9003', kev_due_date: '2026-10-01' }),
    row({ id: 'CVE-2026-9004', is_kev: true }), row({ id: 'CVE-2026-9005', has_public_exploit: true }),
    row({ id: 'CVE-2026-9006', has_poc: true, poc_urls: ['https://x/a', 'https://x/a/'] }),
    row({ id: 'CVE-2026-9007', cvss: 0, epss: 0, epss_percentile: 0 }),
  ];
  const lifecycle = { releases: [
    { product_slug: 'x', cycle: '1', lifecycle_status: 'EOL', eol_date: '2026-13-40' },
    { product_slug: 'x', cycle: '1', lifecycle_status: 'EOL' },
    { product_slug: 'x', cycle: 'bad cycle', lifecycle_status: 'SUPPORTED' },
  ], unavailable: [{ slug: 'openssh' }] };
  const q = Object.fromEntries(CTX.qualityChecks(cves, { lifecycle }).map(c => [c.id, c]));
  assert.deepEqual(q.cve_id_invalid.examples, ['CVE-2026-1']);
  assert.deepEqual(q.cve_duplicate.examples, ['CVE-2026-9001']);
  assert.equal(q.kev_ransom_without_kev.count, 1);
  assert.equal(q.kev_due_without_kev.count, 1);
  assert.equal(q.kev_without_due.count, 1);
  assert.equal(q.edb_flag_without_url.count, 1);
  assert.equal(q.poc_duplicate_url.count, 1);
  assert.equal(q.cvss_missing.status, 'info', '비어 있는 값은 경고가 아니라 정보');
  assert.equal(q.epss_missing.count, 1);
  assert.equal(q.lifecycle_bad_date.count, 1);
  assert.equal(q.lifecycle_duplicate_release.count, 1);
  assert.equal(q.lifecycle_bad_cycle.count, 1);
  assert.equal(q.lifecycle_bad_status.count, 1);
  assert.equal(q.lifecycle_unavailable.status, 'info');
  const withCatalog = Object.fromEntries(CTX.qualityChecks(
    [row({ id: 'CVE-2026-9100', is_kev: true, kev_due_date: '2026-01-01' }), row({ id: 'CVE-2026-9101' })],
    { kevCatalog: new Set(['CVE-2026-9101']) }).map(c => [c.id, c]));
  assert.equal(withCatalog.kev_catalog_not_flagged.count, 1);
  assert.equal(withCatalog.kev_flag_not_in_catalog.count, 1);
});

test('검색어 해석 — has/no/unknown 키 · corr 코드 · release 형식', () => {
  const s = { PATCH_AVAILABLE: 'no', PUBLIC_EXPLOIT: 'yes', AUTOMATABLE: 'unknown' };
  assert.ok(CTX.stateQuery(s, 'patch', 'no'));
  assert.ok(!CTX.stateQuery(s, 'patched', 'no'), '예전 이름 patched · rules 는 지웠다 (2026-11 필터 정리)');
  assert.ok(!CTX.stateQuery({ PUBLIC_DETECTION: 'yes' }, 'rules', 'yes'));
  assert.ok(CTX.stateQuery({ PUBLIC_DETECTION: 'yes' }, 'detection', 'yes'));
  assert.ok(CTX.stateQuery(s, 'exploit', 'yes'));
  assert.ok(CTX.stateQuery(s, 'auto', 'unknown'));
  assert.ok(!CTX.stateQuery(s, 'bogus', 'yes'));
  assert.ok(CTX.correlationQuery(['KEV_EOL'], 'kev_eol'));
  assert.ok(CTX.correlationQuery(['KEV_EOL'], 'kev-eol'));
  assert.ok(!CTX.correlationQuery(['KEV_EOL'], 'nope'));
  assert.deepEqual(CTX.parseRelease('windows/10-22h2'), { slug: 'windows', cycle: '10-22h2' });
  assert.equal(CTX.parseRelease('windows'), null);
});

test('CI 사전 계산 — 브라우저 계산과 같은 결과, 지문, 직렬화 왕복', () => {
  const cves = fx('dashboard_cves.json');
  const stats = fx('dashboard_stats.json');
  const products = fx('dashboard_products.json');
  const packages = fx('dashboard_packages.json');
  const out = build({ cves, stats, products, packages, lifecycle: LCDATA, aliases: ALIASES },
                    new Date(`${TODAY}T12:00:00Z`));
  assert.equal(out.schema, 1);
  assert.equal(out.as_of, TODAY);
  assert.ok(CTX.sameFingerprint(out.inputs,
    CTX.fingerprint({ cves, stats, products, packages, lifecycle: LCDATA, aliases: ALIASES })));
  assert.ok(!CTX.sameFingerprint(out.inputs, CTX.fingerprint({ cves, stats: Object.assign({}, stats, { generated_at: 'x' }),
    products, packages, lifecycle: LCDATA, aliases: ALIASES })), '다른 판의 파일이면 지문이 다르다');
  const m = LC.createMatcher(LCDATA, ALIASES);
  const affectedOf = productDecoder(products);
  const norm = r => JSON.stringify({ e: r.entries.map(e => [e.slug, e.rel.cycle, e.via, e.key]), u: r.unresolved, n: r.untracked,
                                     p: r.partial });
  for (const cve of cves) {
    const aff = affectedOf(cve);
    const dec = LC.decodeMatch(out.lifecycle[cve.id] || null, aff.length, m.releaseIndex);
    assert.ok(dec, cve.id);
    assert.equal(norm(LC.reduceMatch(dec)), norm(m.forCve(aff, (packages.packages || {})[cve.id])), cve.id);
  }
  assert.equal(LC.decodeMatch({ i: [['windows', 'pattern', 'k', ['no-such-cycle'], 0, 0]] }, 1, m.releaseIndex), null,
               '현재 수명주기 데이터에 없는 사이클이면 되돌린다');
  assert.equal(out.stats.total, cves.length);
  assert.equal(out.stats.signals.CISA_KEV.yes, cves.filter(c => c.is_kev).length);
  assert.ok(out.quality.some(q => q.id === 'kev_catalog' && q.status === 'skipped'));
});
