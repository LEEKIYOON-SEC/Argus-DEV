'use strict';
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadDashboard, withFixture, readJson, filterIds, RESET } = require('./helpers/dashboard_vm');
const { collect, rowIds } = require('./helpers/dashboard_scenarios');
const { build } = require('../src/build_context.js');

const TODAY = '2026-09-27';
const ALIASES = require('../data/lifecycle_aliases.json');
// 화면 핵심(뷰 모델 · 목록 · 상세 · 대시보드) — 파생 모듈(lifecycle.js · context.js · entities.js)이 없어도 동작해야 한다.
const CORE = [{ file: 'docs/js/viewmodel.js' }, { file: 'docs/js/cve-dashboard.js' }, { file: 'docs/js/cve-detail.js' },
              { file: 'docs/js/dashboard-view.js' }, { file: 'docs/js/sources-view.js' }];
const FULL = [{ file: 'docs/js/lifecycle.js' }, { file: 'docs/js/context.js' }, { file: 'docs/js/entities.js' },
              { file: 'docs/js/cwe-data.js' }, { file: 'docs/js/cwe.js' }, ...CORE, { file: 'docs/js/lifecycle-view.js' }];

function dashboard({ files = FULL, lifecycle = true } = {}) {
  const d = withFixture(loadDashboard(files));
  if (lifecycle) {
    d.ctx.__lc = [readJson('lifecycle_sample.json'), ALIASES];
    d.run(`setLifecycle(__lc[0], __lc[1]); lcToday = ${JSON.stringify(TODAY)};`);
  }
  d.run('dataReady = true;');
  return d;
}

const BASELINE = readJson('dashboard_baseline.json').result;
const ids = arr => [...arr].sort();
const search = (d, q) => ids(filterIds(d, `activeFilters.search = ${JSON.stringify(q)};`));
const ALL = ids(BASELINE.searches['']);
const cve = n => `CVE-2026-${String(n).padStart(4, '0')}`;
const unesc = t => String(t).replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&amp;/g, '&');

// 변경 전(0f68020) 기준과 의미로 비교한다 — 목록·상세는 새 화면이라 HTML 대신 행 ID 순서·ID·제목만.
// has:nuclei · has:edb · has:ransom · has:foo 는 기존 버그(전부 통과)를 고쳤으므로 아래에서 따로 확인한다.
const FIXED_BUGS = ['has:nuclei', 'has:edb', 'has:ransom', 'has:foo'];
// 의도한 변경 — 대시보드 KPI 정의(INVARIANTS §6): CISA KEV 는 is_kev 만, 무기화 = Metasploit ∪ Exploit-DB(nuclei 제외),
// 24시간 칸 설명은 '신규'가 아니라 '알림·갱신'. 새 값은 아래 'KPI' 테스트가 확인한다. 예전 묶음(KPI_TILES)은 그대로 비교한다.
const CHANGED_KPI = ['stat-kev', 'stat-weapon', 'stat-24h-sub'];
// 영향 제품 순위의 툴팁 문구만 바꿨다(말투 정리). 칸 구성 · 숫자 · 누르면 거는 필터는 그대로 비교한다.
// 제품 이름은 이제 onclick 코드가 아니라 data-product 에 싣는다(이름의 따옴표 · 역슬래시가 코드로 읽히지 않게). 걸리는 필터는 같다.
const noTitles = html => String(html).replace(/ title="[^"]*"/g, '')
  .replace(/data-product="([^"]*)" onclick="filterByProduct\(this\.dataset\.product\)"/g, "onclick=\"filterByProduct('$1')\"");
function semantic(out) {
  const o = JSON.parse(JSON.stringify(out));
  o.ui.rows = rowIds(o.ui.rows);
  o.ui.emptyRows = /empty-state/.test(o.ui.emptyRows);
  for (const k of Object.keys(o.detail)) o.detail[k] = { id: o.detail[k].id, title: o.detail[k].title };
  for (const q of FIXED_BUGS) delete o.searches[q];
  for (const k of CHANGED_KPI) delete o.stats[k];
  o.stats.products = noTitles(o.stats.products);
  return o;
}

test('회귀: 검색·필터·정렬·페이지·통계·필터 목록·CSV/JSON/STIX 가 변경 전과 같다', () => {
  const now = semantic(collect(dashboard()));
  const base = semantic(BASELINE);
  for (const section of Object.keys(base)) {
    for (const key of Object.keys(base[section])) {
      assert.deepEqual(now[section][key], base[section][key], `${section}.${key}`);
    }
  }
});

test('회귀: 수명주기 데이터를 못 받아도 기존 동작이 같다', () => {
  assert.deepEqual(semantic(collect(dashboard({ lifecycle: false }))), semantic(BASELINE));
});

test('회귀: 수명주기·파생 모듈이 없어도 목록·검색·내보내기가 동작한다', () => {
  assert.deepEqual(semantic(collect(dashboard({ files: CORE, lifecycle: false }))), semantic(BASELINE));
});

test('기존 has:* 는 뜻 그대로, 전부 통과하던 has:nuclei · edb · ransom · 잘못된 값은 고쳤다', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'has:kev'), [cve(1), cve(4), cve(10)]);
  assert.deepEqual(search(d, 'has:msf'), [cve(1), cve(2), cve(7), cve(11)], '기존 무기화 묶음(MSF · EDB · nuclei) 그대로');
  assert.deepEqual(search(d, 'has:poc'), [cve(3), cve(14)]);
  assert.deepEqual(search(d, 'has:rules'), [cve(1), cve(9)]);
  assert.deepEqual(search(d, 'has:ai'), [cve(5)]);
  assert.deepEqual(search(d, 'has:auto'), [cve(6)]);
  assert.deepEqual(search(d, 'has:patched'), [cve(8)]);
  for (const q of ['has:kev', 'has:msf', 'has:poc', 'has:rules', 'has:ai', 'has:auto', 'has:patched']) {
    assert.deepEqual(search(d, q), ids(BASELINE.searches[q]), `${q} 는 변경 전과 같다`);
  }
  assert.deepEqual(BASELINE.searches['has:nuclei'].length, ALL.length, '변경 전: 전부 통과(버그)');
  assert.deepEqual(search(d, 'has:nuclei'), [cve(2), cve(7)]);
  assert.deepEqual(search(d, 'has:edb'), [cve(2), cve(11)]);
  assert.deepEqual(search(d, 'has:ransom'), [cve(1)]);
  assert.deepEqual(search(d, 'has:foo'), [], '모르는 값은 아무것도 통과시키지 않는다');
});

test('새 검색어 — 출처별 · 파생 신호 · 없음(no:) · 모름(unknown:)', () => {
  const d = dashboard();
  assert.deepEqual(search(d, 'has:cisa-kev'), [cve(1), cve(10)]);
  assert.deepEqual(search(d, 'has:vulncheck-kev'), [cve(4)]);
  assert.deepEqual(search(d, 'has:ssvc-active'), [cve(4)]);
  assert.deepEqual(search(d, 'has:exploit'), [cve(1), cve(2), cve(3), cve(11), cve(14)], 'EDB · MSF · PoC (nuclei 제외)');
  assert.deepEqual(search(d, 'has:metasploit'), [cve(1)]);
  assert.deepEqual(search(d, 'has:detection'), [cve(1), cve(2), cve(7), cve(9)], '룰 + nuclei 점검 템플릿');
  assert.deepEqual(search(d, 'has:patch'), search(d, 'has:patched'));
  assert.deepEqual(search(d, 'no:patch'), [cve(3)], 'OSV 에 패키지는 있는데 수정 버전 기록이 없음');
  assert.deepEqual(search(d, 'unknown:patch'), ALL.filter(x => ![cve(3), cve(8)].includes(x)), 'OSV 기록 없음은 모름');
  assert.deepEqual(search(d, 'has:high-epss'), [cve(1), cve(2), cve(6), cve(10), cve(14)]);
  assert.deepEqual(search(d, 'unknown:high-epss'), [cve(16)], 'EPSS 0 은 미채점');
  assert.deepEqual(search(d, 'has:critical'), search(d, 'cvss:>=9'));
  assert.deepEqual(search(d, 'unknown:critical'), [cve(5)], 'CVSS 0 은 점수 없음');
  assert.deepEqual(search(d, 'has:eol'), search(d, 'lifecycle:eol'));
  assert.deepEqual(search(d, 'unknown:ransom'), ALL.filter(x => x !== cve(1)), '랜섬웨어는 Known 이 아니면 모름');
  assert.deepEqual(search(d, 'no:ransom'), [], 'KEV 는 "아님"을 주지 않는다');
  assert.deepEqual(search(d, 'unknown:auto'), ALL.filter(x => x !== cve(6)));
  assert.deepEqual(search(d, 'lifecycle:security-support'), search(d, 'lifecycle:security'));
  assert.deepEqual(search(d, 'release:windows/7-sp1'), [cve(10)]);
  assert.deepEqual(search(d, 'release:nginx/1.25'), [cve(2)]);
  assert.deepEqual(search(d, 'release:windows'), [], '제품/사이클 형식이 아니면 통과시키지 않는다');
  assert.deepEqual(search(d, 'no:bogus'), []);
  assert.deepEqual(search(d, 'corr:bogus'), []);
});

test('상관 — corr:<코드> · 카드 검색어 · 집계 숫자가 모두 같다 (대시보드 숫자 = 누른 뒤 목록)', () => {
  const d = dashboard();
  const agg = d.run('liveAggregate()');
  for (const c of d.run('ArgusContext.CORRELATIONS')) {
    const byCode = search(d, `corr:${c.code.toLowerCase()}`);
    const byQuery = search(d, c.query);
    assert.deepEqual(byQuery, byCode, `${c.code}: ${c.query}`);
    assert.equal(agg.correlations[c.code], byCode.length, `${c.code} 집계`);
  }
  assert.deepEqual(search(d, 'corr:kev_eol'), [cve(10)]);
  assert.deepEqual(search(d, 'corr:exploit_no_fix'), [cve(3)], '공개 exploit + OSV 수정 기록 없음');
  assert.deepEqual(search(d, 'corr:kev_ransomware'), [cve(1)]);
});

test('KPI — 6칸, 정의가 바뀐 칸(CISA KEV · 무기화 · 24시간)과 숫자 = 누른 뒤 목록 건수', () => {
  const d = dashboard();
  d.run('renderStats(); renderDashboard();');
  const kpis = d.el('dash-kpis').innerHTML;
  const tiles = [...kpis.matchAll(/data-query="([^"]*)"[\s\S]*?kpi-label">([^<]+)<\/span>\s*<span class="kpi-value" id="([^"]+)">([\d,-]+)</g)]
    .map(m => ({ query: m[1], label: m[2], id: m[3], value: Number(m[4].replace(/,/g, '')) }));
  assert.deepEqual(tiles.map(t => t.label), ['추적 중 CVE', '24시간 알림·갱신', 'CISA KEV', '무기화', '공개 PoC', 'AI 발견']);
  assert.deepEqual(tiles.map(t => t.value), [16, 5, 2, 3, 2, 1]);
  assert.deepEqual(tiles.map(t => t.query), ['', 'recent:24h', 'has:cisa-kev', 'has:weaponized', 'has:poc', 'has:ai']);
  for (const t of tiles) assert.equal(search(d, t.query).length, t.value, `${t.label}: ${t.query || '(전체)'}`);
  assert.deepEqual(search(d, 'has:cisa-kev'), [cve(1), cve(10)], 'CISA KEV 만 — VulnCheck · SSVC active 는 악용 근거(has:kev)에만');
  assert.deepEqual(search(d, 'has:weaponized'), [cve(1), cve(2), cve(11)], 'Metasploit ∪ Exploit-DB — nuclei 점검 템플릿(CVE-7)은 넣지 않는다');
  assert.deepEqual(search(d, 'recent:24h'), [cve(12), cve(13), cve(14), cve(15), cve(16)], 'export 시각 기준 24시간 안의 Argus 시각');
  // 숫자 아래 줄 — 변화를 셀 수 없으면(KEV 등재일 파일 전) 출처별 건수를 적는다
  assert.match(kpis, /id="stat-kev">2<\/span>\s*<span class="kpi-sub">악용 근거 전체 3건</, 'CVE-1 · 4(VulnCheck + SSVC active) · 10');
  assert.match(kpis, /<span class="kpi-sub">MSF 1 · EDB 2</);
  assert.match(kpis, /title="Metasploit\(MSF\) 모듈이나 Exploit-DB\(EDB\) 항목이 있는 CVE입니다\. Metasploit 1건 · Exploit-DB 2건/, '약칭은 설명에 풀어 쓴다');
  assert.match(kpis, /id="stat-24h">5<\/span>\s*<span class="kpi-sub">Critical 0 · KEV 0</, '24시간 알림·갱신 중 Critical · CISA KEV');
  assert.match(kpis, /id="stat-total">16<\/span>\s*<span class="kpi-sub">최근 7일 공개 없음</);
  assert.doesNotMatch(kpis, /—/, '칸 안의 설명에 줄표를 쓰지 않는다');
  // renderStats 가 쓰는 칸(예전 id)도 같은 값
  assert.deepEqual(['stat-total', 'stat-24h', 'stat-kev', 'stat-weapon', 'stat-poc', 'stat-ai'].map(id => d.el(id).textContent), ['16', '5', '2', '3', '2', '1']);
  assert.equal(d.el('stat-24h-sub').textContent, '새 공개와 상태 변경 포함');
  // 예전 KPI 네 칸의 신호 묶음은 기존 검색어(has:kev · has:msf)의 뜻으로 남는다
  assert.deepEqual(JSON.parse(JSON.stringify(d.run('KPI_TILES.map(sig => allCves.filter(c => cveHasSignal(c, sig)).length)'))), BASELINE.stats.kpi);
});

test('대시보드 — 추이 · 상관 · 최근 CVE · 동시 발생 행렬 · 관련 검색어 (숫자 = 목록)', () => {
  const d = dashboard();
  d.run('renderDashboard();');
  assert.match(d.el('dash-meta').innerHTML, /수명주기 기준일 <b>2026-09-27<\/b>/);
  assert.match(d.el('dash-asof').textContent, /기준 · 추적 중 CVE 16건$/);
  // 추이 — 최근 30일(2026-08-29 ~ 09-27) CVE 공개일별. 공개일 09-19 인 13건만 창 안에 있다. 선 하나 + 날짜마다 마우스 칸.
  const ov = d.el('dash-overview').innerHTML;
  assert.equal((ov.match(/class="ov-col/g) || []).length, 30);
  assert.equal((ov.match(/class="ov-line"/g) || []).length, 1, '한 계열 선');
  assert.match(ov, /합계 <b>13<\/b>건 · 하루 최대 <b>13<\/b>건\(09\.19\) · 최근 7일 <b>0<\/b>건/);
  assert.match(ov, /<td>2026-09-19<\/td><td><b>13<\/b><\/td><td>3<\/td>/, '표로 보기 — 날짜 · 합계 · 심각도별');
  // 상관 — 10개, 건수순, 누르면 같은 조건
  const corr = d.el('dash-corr').innerHTML;
  assert.equal((corr.match(/class="corr-card/g) || []).length, 10);
  assert.match(corr, /data-query="has:cisa-kev lifecycle:eol"[\s\S]*?corr-n">1</);
  assert.match(corr, /data-query="has:cisa-kev has:ransom"[\s\S]*?corr-scope">나머지는 미확인</, '랜섬웨어처럼 "없음"이 없는 신호는 비율을 쓰지 않는다');
  assert.match(corr, /data-query="has:cisa-kev has:exploit"[\s\S]*?corr-scope">CISA KEV 중 50%</, '분모가 첫 신호 전체면 그 이름으로');
  assert.match(corr, /data-query="has:cisa-kev lifecycle:eol"[\s\S]*?corr-scope">판정된 1건 중 100%</, 'EOL 여부를 아는 CVE 만 분모');
  const nums = [...corr.matchAll(/corr-n">([\d,]+)</g)].map(m => Number(m[1]));
  assert.deepEqual(nums, [...nums].sort((a, b) => b - a), '건수 많은 순');
  // 최근 CVE — 공개일 순, 같은 날이면 Argus 시각 순
  const recent = [...d.el('dash-recent').innerHTML.matchAll(/data-cve="([^"]+)"/g)].map(m => m[1]);
  assert.deepEqual(recent, [16, 15, 14, 13, 12, 10, 9, 8].map(cve));
  // 행렬 — 칸마다 두 신호 모두 있음 건수 = 그 검색어의 목록 건수
  const mx = d.el('dash-matrix').innerHTML;
  const cells = [...mx.matchAll(/class="mx-cell mx-(\d)" data-query="([^"]+)"[^>]*>([\d,]+)</g)];
  assert.ok(cells.length > 0);
  for (const [, , q, n] of cells) assert.equal(search(d, unesc(q)).length, Number(n.replace(/,/g, '')), q);
  const zeros = (mx.match(/class="mx-cell mx-0"/g) || []).length;
  assert.equal(cells.length + zeros, 36, '9개 신호의 두 개씩 조합');
  assert.match(mx, /class="mx-row" data-query="has:cisa-kev"/, '줄 이름 = 그 신호 전체');
  const axes = [...mx.matchAll(/class="mx-row" data-query="([^"]+)"[\s\S]*?<small>([\d,]+)<\/small>/g)];
  assert.equal(new Set(axes.map(m => m[1])).size, 9, '신호 9개 모두 줄 또는 칸 머리에 전체 건수');
  for (const [, q, n] of axes) assert.equal(search(d, unesc(q)).length, Number(n.replace(/,/g, '')), `전체 ${q}`);
  const chips = [...d.el('dash-rel-chips').innerHTML.matchAll(/data-query="([^"]+)"[^>]*><span class="rel-name">[^<]+<\/span><code>[^<]+<\/code><b>([\d,]+)</g)];
  assert.ok(chips.length > 0 && chips.length <= 6);
  for (const [, q, n] of chips) assert.equal(search(d, unesc(q)).length, Number(n), q);
});

test('Data Sources — 외부 출처 한 표에 건수 · 갱신 · 이용 조건(라이선스 전문 링크), 이용 조건은 이 표 한 곳에만', () => {
  const d = dashboard();
  d.run('renderSources();');
  const reg = d.el('src-registry').innerHTML;
  const ids = d.run('ArgusEntities.SOURCE_GROUPS').flatMap(g => g.ids);
  for (const id of ids) assert.equal((reg.match(new RegExp(`id="src-${id}"`, 'g')) || []).length, 1, id);
  assert.equal((reg.match(/<tr id="src-/g) || []).length, ids.length);
  for (const hidden of ['gemma', 'gemini', 'argus', 'rule-index', 'nvd']) assert.doesNotMatch(reg, new RegExp(`id="src-${hidden}"`), hidden);
  assert.doesNotMatch(reg, /Gemma|Gemini|Google AI Studio|무료 티어/, 'AI 도구 · 요금제는 출처 표에 싣지 않는다');
  assert.doesNotMatch(reg, /\.json|캐시/, '파일 이름 · 캐시 설명은 싣지 않는다');
  assert.match(reg, /id="src-cisa-kev"[\s\S]*?<b>2<\/b>/, 'CISA KEV 에 기록이 있는 추적 CVE 2건');
  assert.match(reg, /id="src-sigma"[\s\S]*?<b>1<\/b>/, 'Sigma 룰이 있는 CVE 1건 — 전체 목록에서 룰이 온 곳으로 센다');
  assert.match(reg, /id="src-et-open"[\s\S]*?href="https:\/\/rules\.emergingthreats\.net\/open\/suricata-7\.0\/LICENSE"[^>]*>BSD/);
  assert.match(reg, /id="src-snort-community"[\s\S]*?href="https:\/\/www\.gnu\.org\/licenses\/old-licenses\/gpl-2\.0\.html"[^>]*>GPLv2/);
  assert.match(reg, /id="src-sigma"[\s\S]*?href="https:\/\/github\.com\/SigmaHQ\/Detection-Rule-License"[^>]*>DRL 1\.1/);
  assert.match(reg, /id="src-splunk"[\s\S]*?href="https:\/\/github\.com\/splunk\/security_content\/blob\/develop\/LICENSE"[^>]*>Apache-2\.0/);
  assert.match(reg, /id="src-cve-record"[\s\S]*?Legal\/TermsOfUse"[^>]*>CVE 이용약관[\s\S]*?terms-of-use"[^>]*>NVD 이용약관/, 'NVD 는 CVE 레코드 행에 합친다');
  assert.match(d.el('src-meta').textContent, /기준 · 추적 중 CVE 16건/);
  // 예약 주기 — yml 예약 · 캐시 수명 그대로. CVE 레코드는 5분 수집(변경분), SSVC 는 CVE 레코드 안에 함께 온다
  assert.match(reg, /<th[^>]*>예약 주기<\/th>/);
  assert.doesNotMatch(reg, /<th>갱신<\/th>/);
  assert.match(reg, /id="src-cve-record"[\s\S]*?data-label="예약 주기">5분마다 \(변경분\)</);
  assert.match(reg, /id="src-cisa-adp"[\s\S]*?data-label="예약 주기">5분마다 \(CVE 레코드와 함께\)</);
  assert.match(reg, /id="src-cisa-kev"[\s\S]*?data-label="예약 주기">매시</);
});

test('탐지 룰 목록 — 룰마다 한 줄에 라이선스 전문 · 저작권 · 작성자 · 원문 링크, 라이선스가 없는 YARA 는 본문 없이 링크만', () => {
  const d = dashboard();
  const html = d.run(`renderRuleList({ id: 'CVE-X', rules: {
    sigma: { code: 'title: s', source: 'SigmaHQ', license: 'DRL 1.1', author: 'A', url: 'https://github.com/SigmaHQ/sigma/blob/master/r.yml' },
    network: [{ engine: 'suricata7', source: 'Suricata 7 ET Open', license: 'MIT', code: 'alert x' }],
    yara: { engine: 'yara', source: 'YARA Forge', license: '룰별 상이', license_url: 'N/A', author: 'B',
            url: 'https://github.com/fboldewin/YARA-rules/blob/x/r.yar', code: 'rule leak {}' } } })`);
  const items = html.split('<div class="rule-item">').slice(1);
  assert.deepEqual(items.map(x => /class="rule-eng">([^<]+)/.exec(x)[1]), ['Sigma', 'Suricata 7', 'YARA'], '근거 표와 같은 엔진 순서');
  assert.match(items[0], /라이선스 <a href="https:\/\/github\.com\/SigmaHQ\/Detection-Rule-License"[^>]*>DRL 1\.1 ↗<\/a> · 작성자 A</);
  assert.match(items[0], /class="rule-open" href="https:\/\/github\.com\/SigmaHQ\/sigma\/blob\/master\/r\.yml"[^>]*>원문 ↗/, 'DRL 1.1 은 룰 링크를 요구한다');
  assert.match(items[1], /<b>ET Open<\/b>[\s\S]*?라이선스 <a href="https:\/\/rules\.emergingthreats\.net\/open\/suricata-7\.0\/LICENSE"[^>]*>BSD ↗<\/a> · © 2003-2026 Emerging Threats/);
  assert.doesNotMatch(html, /License: |MIT/, '옛 표기(ET Open MIT)를 그대로 싣지 않는다');
  assert.doesNotMatch(items[1], /class="rule-open"/, 'msg 에 분류가 없는 ET 룰은 원문 파일을 알 수 없어 링크를 달지 않는다');
  assert.doesNotMatch(html, /rule leak/, '라이선스가 없는 저장소의 YARA 본문은 싣지 않는다');
  assert.match(items[2], /원 저장소에 라이선스 파일이 없어 본문은 싣지 않습니다/);
  assert.match(items[2], /href="https:\/\/github\.com\/fboldewin\/YARA-rules\/blob\/x\/r\.yar"[^>]*>원문 ↗/);
  assert.doesNotMatch(items[2], /rule-body-btn|copy-btn/, '본문이 없으면 본문 · 복사 버튼도 없다');
  // 본문은 처음에 닫혀 있고 '본문'으로 펼친다. 한 줄짜리 룰도 줄을 바꿔 끝까지 보이게(CSS).
  assert.match(items[0], /<button type="button" class="rule-body-btn" onclick="toggleRuleBody\(this\)" aria-expanded="false" aria-controls="d-rule-0">본문<\/button>/);
  assert.match(items[0], /<pre class="rule-preview" id="d-rule-0" hidden>title: s<\/pre>/);
  // BSD · MIT 저장소의 YARA 룰은 저작권 문구를 함께 적는다 (문구는 export 가 원 저장소 LICENSE 에서 옮김)
  const bsd = d.run(`renderRuleList({ id: 'CVE-Y', rules: { yara: { engine: 'yara', source: 'YARA Forge', license: 'BSD-2-Clause',
    holder: 'Copyright 2022 by Volexity, Inc.', license_url: 'https://github.com/volexity/threat-intel/blob/x/LICENSE.txt',
    author: 'threatintel@volexity.com', url: 'https://github.com/volexity/threat-intel/blob/x/y.yar', code: 'rule v {}' } } })`);
  assert.match(bsd, /라이선스 <a href="https:\/\/github\.com\/volexity\/threat-intel\/blob\/x\/LICENSE\.txt"[^>]*>BSD-2-Clause[^<]*<\/a> · Copyright 2022 by Volexity, Inc\. · 작성자 threatintel@volexity\.com/);
  assert.match(bsd, /rule v \{\}/);
  assert.equal(d.run("renderRuleList({ id: 'CVE-Z', rules: {} })"), '', '룰이 없으면 목록도 없다');
});

test('탐지 룰 목록 — ET Open 은 분류 파일 + SID 위치, Snort Community 는 snort.org 룰 설명, nuclei 는 템플릿 원문', () => {
  const d = dashboard();
  const et = 'alert http any any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Acme RCE (CVE-2026-0001)"; sid:2071774; rev:1;)';
  const html = d.run(`renderRuleList({ id: 'CVE-X', _nuclei_url: 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/x.yaml', rules: {
    nuclei: { source: 'nuclei-templates', author: 'pd', url: '' },
    network: [
      { engine: 'suricata7', source: 'Suricata 7 ET Open', code: ${JSON.stringify(et)}, url: '' },
      { engine: 'snort2', source: 'Snort 2.9 ET Open', code: ${JSON.stringify(et.replace('ET WEB_SPECIFIC_APPS', 'ET TROJAN'))}, url: '' },
      { engine: 'snort3', source: 'Snort 3 Community', code: 'alert http (msg:"SERVER-WEBAPP x"; sid:62506; rev:1;)', url: '' },
      { engine: 'suricata5', source: 'Suricata 5 ET Open', code: ${JSON.stringify(et.replace('ET WEB_SPECIFIC_APPS', 'ET NEWCAT'))}, url: '' }] } })`);
  const items = html.split('<div class="rule-item">').slice(1);
  assert.deepEqual(items.map(x => /class="rule-eng">([^<]+)/.exec(x)[1]), ['Suricata 7', 'Suricata 5', 'Snort 3', 'Snort 2', 'nuclei']);
  assert.match(items[0], /<b>ET Open<\/b><code>SID 2071774<\/code>/);
  assert.match(items[0], /href="https:\/\/rules\.emergingthreats\.net\/open\/suricata-7\.0\/rules\/emerging-web_specific_apps\.rules#:~:text=sid:2071774;"[^>]*>원문 파일 ↗ <small>5\.7MB<\/small>/);
  assert.doesNotMatch(items[1], /class="rule-open"/, '분류 표에 없는 분류(새 분류)는 없는 파일로 보내지 않는다');
  assert.match(items[2], /<b>Snort Community<\/b><code>SID 1:62506<\/code>[\s\S]*?href="https:\/\/www\.snort\.org\/rule-docs\/1-62506"[^>]*>룰 설명 ↗/);
  assert.match(items[2], /라이선스 <a href="https:\/\/www\.gnu\.org\/licenses\/old-licenses\/gpl-2\.0\.html"[^>]*>GPLv2 ↗<\/a> · © 2001-2026 Sourcefire, Inc\. 및 각 작성자/);
  assert.match(items[3], /href="https:\/\/rules\.emergingthreats\.net\/open\/snort-2\.9\.0\/rules\/emerging-trojan\.rules#:~:text=sid:2071774;"[^>]*>원문 파일 ↗ <small>19\.1MB<\/small>/, 'Snort 2.9 판에만 있는 분류');
  assert.match(items[4], /class="rule-eng">nuclei<small>점검 템플릿<\/small>/);
  assert.match(items[4], /href="https:\/\/github\.com\/projectdiscovery\/nuclei-templates\/blob\/main\/http\/cves\/x\.yaml"[^>]*>원문 ↗/);
  assert.match(items[4], /공격 탐지 룰이 아니며 공격에도 쓰일 수 있어 본문은 싣지 않습니다/, 'nuclei 는 공격 탐지 룰이 아님을 적는다(§13)');
  assert.doesNotMatch(items[4], /rule-body-btn|<pre/, '점검 템플릿은 본문을 싣지 않는다');
  // rule_engines 에만 있고 룰 본문이 없는 네트워크 엔진 — 룰이 온 곳(ET Open · Snort Community)을 몰라 라이선스를 짐작해 적지 않는다
  const bare = d.run(`renderRuleList({ id: 'CVE-B', rule_engines: ['snort2'], rules: {} })`);
  assert.match(bare, /class="rule-eng">Snort 2<\/span>[\s\S]*?<b>ET Open · Snort Community<\/b><\/span>/);
  assert.doesNotMatch(bare, /라이선스|class="rule-open"|rule-body-btn/);
});

test('대시보드 — 전체 데이터 전에 CI 사전 계산으로 먼저 그리고, 숫자는 같다', () => {
  const live = dashboard();
  live.run('renderDashboard();');
  const liveCorr = live.el('dash-corr').innerHTML;
  const fx = { cves: readJson('dashboard_cves.json'), stats: readJson('dashboard_stats.json'),
               products: readJson('dashboard_products.json'), packages: readJson('dashboard_packages.json') };
  const ctx = build(Object.assign({ lifecycle: readJson('lifecycle_sample.json'), aliases: ALIASES }, fx),
                    new Date(`${TODAY}T12:00:00Z`));
  const early = withFixture(loadDashboard(FULL));
  early.ctx.__ctx = ctx;
  early.run('allCves = []; dataReady = false; setContext(__ctx); renderDashboard();');
  assert.match(early.el('dash-meta').innerHTML, /CI 사전 계산/);
  const earlyCorr = early.el('dash-corr').innerHTML;
  const nums = html => [...html.matchAll(/corr-n">([\d,]+)</g)].map(m => m[1]);
  assert.deepEqual(nums(earlyCorr), nums(liveCorr));
  early.run("statsData = Object.assign({}, statsData, { generated_at: 'other' }); renderDashboard();");
  assert.match(early.el('dash-corr').innerHTML, /불러오는 중/, '다른 판의 사전 계산은 쓰지 않는다');
});

test('사전 계산 매핑 — 지문이 맞으면 쓰고, 결과는 직접 매칭과 같다', () => {
  const fx = { cves: readJson('dashboard_cves.json'), stats: readJson('dashboard_stats.json'),
               products: readJson('dashboard_products.json'), packages: readJson('dashboard_packages.json') };
  const lcData = readJson('lifecycle_sample.json');
  const ctx = build(Object.assign({ lifecycle: lcData, aliases: ALIASES }, fx), new Date(`${TODAY}T12:00:00Z`));
  const plain = dashboard();
  const pre = withFixture(loadDashboard(FULL));
  Object.assign(pre.ctx, { __ctx: ctx, __raw: fx, __lc: [lcData, ALIASES] });
  pre.run(`rawFiles.products = __raw.products; rawFiles.packages = __raw.packages; setContext(__ctx);
           setLifecycle(__lc[0], __lc[1]); lcToday = ${JSON.stringify(TODAY)}; dataReady = true;`);
  assert.equal(pre.run('contextValid'), true);
  for (const c of fx.cves) {
    const q = `JSON.stringify((r => ({ e: r.entries.map(e => [e.slug, e.rel.cycle, e.via]), u: r.unresolved, n: r.untracked, p: r.partial }))(cveLifecycle(allCves.find(x => x.id === ${JSON.stringify(c.id)}))))`;
    assert.equal(pre.run(q), plain.run(q), c.id);
  }
  pre.run("rawFiles.products = Object.assign({}, rawFiles.products, { generated_at: 'changed' }); validateContext();");
  assert.equal(pre.run('contextValid'), false, '영향 제품 파일이 바뀌면 사전 계산 매핑을 버린다');
});

test('목록 — 5칸, 출처가 확인한 것만 칩, 없음 · 미확인은 빈칸', () => {
  const d = dashboard();
  filterIds(d, '');
  const html = d.el('cve-table-body').innerHTML;
  const row = id => html.split('<tr ').find(r => r.includes(`data-id="${id}"`));
  assert.equal(rowIds(html).length, 16);
  assert.equal((row(cve(1)).match(/<td /g) || []).length, 5, 'CVE · 요약·영향 제품 · CVSS·EPSS · 위협 신호 · 탐지·수정');
  assert.doesNotMatch(html, /c-lc/, '지원 상태 칸은 없다');
  assert.match(row(cve(1)), /ev-chip ev-exploit[^>]*><i><\/i>KEV<\/span>/, '악용 근거는 출처 이름으로 짧게');
  assert.match(row(cve(1)), /ev-chip ev-exploit[^>]*><i><\/i>랜섬웨어<\/span>/, '랜섬웨어는 따로 한 칩');
  assert.match(row(cve(1)), /ev-chip ev-weapon[^>]*><i><\/i>MSF<\/span>/);
  assert.match(row(cve(2)), /ev-chip ev-weapon[^>]*><i><\/i>EDB<\/span>/);
  assert.doesNotMatch(row(cve(2)), /ev-exploit/, 'nuclei · EDB 만으로 악용 근거가 되지 않는다');
  assert.match(row(cve(6)), /ev-chip ev-auto/);
  assert.match(row(cve(12)), /<span class="c-none" aria-label="확인된 위협 신호 없음"><\/span>/, '신호가 없으면 빈칸');
  assert.match(row(cve(5)), /점수 없음/, 'CVSS 0 은 미확인');
  assert.match(row(cve(16)), /미채점/, 'EPSS 0 은 미확인');
  assert.match(row(cve(5)), /class="sc-sub"[^>]*>0\.04%</, '0.1% 미만은 0.0% 로 적지 않는다');
  assert.deepEqual(['epssPct(0.99999, 1)', 'epssPct(0.99999, 2)', 'epssPct(1, 1)', 'epssPct(0.1234, 2)'].map(x => d.run(x)),
                   ['99.9', '99.99', '100.0', '12.34'], '1 미만 확률을 100% 로 반올림하지 않는다');
  assert.match(row(cve(8)), /class="df df-fix"[^>]*>수정 버전</, 'OSV 수정 버전');
  assert.doesNotMatch(row(cve(3)), /df-fix/, '수정 기록 없음은 빈칸 (상세에 기록 없음으로)');
  assert.match(row(cve(1)), /class="df df-det"[^>]*>탐지 룰</);
  assert.match(row(cve(4)), /ev-chip ev-exploit[^>]*><i><\/i>VulnCheck<b>외 1<\/b><\/span>/, "출처가 여럿이면 '외 N'");
  assert.match(row(cve(14)), /<td class="c-threat"[^>]*><span class="ev-chips">[^]*lc-badge lc-ACTIVE[^>]*>ACTIVE<em>/,
               '지원 상태는 알 때만 위협 신호 칸의 칩으로 (+ 릴리스 이름)');
  assert.doesNotMatch(row(cve(5)), /lc-badge/, '지원 상태를 모르면 칩 없음');
  // 둘째 줄 — 취약점 유형(칩) · 영향 제품 · 영향 버전 · 요약 한 조각
  assert.match(row(cve(3)), /class="c-prod"[^>]*><span class="c-type" title="XSS — 입력값이 웹 페이지에 그대로 실려 방문자 브라우저에서 스크립트가 실행되는 결함 \(CWE-79 Improper Neutralization of Input During Web Page Generation \('Cross-site Scripting'\)\)">XSS<\/span>PHP Group PHP<span class="c-ver"> · 8\.1\.\* 부터 8\.1\.29 이전 외 1<\/span><span class="c-snip"> · fixture description 3<\/span><\/div>/,
               '유형 칩 · 영향 버전 한 줄 표기 · 요약 조각');
  assert.match(row(cve(1)), /<span class="c-type"[^>]*>Out-of-bounds Write<\/span>/);
  assert.match(row(cve(6)), /Oracle Java SE<span class="c-ver"> · 8u112<\/span>/, '단일 버전');
  assert.doesNotMatch(row(cve(6)), /c-type/, 'CWE 가 없으면 유형 칩 없음');
  assert.match(row(cve(1)), /class="c-date" title="알림 시각 toLocaleString\(&quot;ko-KR&quot;,null\)@2026-09-20T03:00:00\.000Z \(알림을 보냈거나 상태가 바뀐 때\. CVE 공개일이 아님\)">/,
               '칸에는 짧게, 마우스를 올리면 전체 시각');
  assert.doesNotMatch(html, /badge-kev|badge-msf/, '예전 위협 배지 스타일을 쓰지 않는다');
  filterIds(d, "activeFilters.search = 'nomatch';");
  assert.match(d.el('cve-table-body').innerHTML, /colspan="5" class="empty-state"/, '5칸');
});

test('목록 — 알림 등급 정렬이면 등급이 바뀌는 곳과 쪽 맨 위에 구분 줄(이름 · 건수 · 기준)', () => {
  const d = dashboard();
  filterIds(d, '');
  const html = d.el('cve-table-body').innerHTML;
  const groups = [...html.matchAll(/<tr class="grp-row grp-(T\d)"><td colspan="5">[^]*?<b>([^<]+)<\/b><span class="grp-n">(\d+)건<\/span><span class="grp-desc">([^<]+)<\/span><\/td><\/tr>/g)]
    .map(m => [m[1], m[2], Number(m[3]), m[4].endsWith(' · 알림 시각 최신순')]);
  assert.deepEqual(groups, [['T0', '관측된 악용', 3, true], ['T1', '무기화 임박', 5, true], ['T2', '관찰', 6, true], ['T3', '신호 없음', 2, true]]);
  // 구분 줄 바로 다음 행이 그 등급의 첫 행
  for (const [tier] of groups) {
    const after = html.slice(html.indexOf(`grp-${tier}`));
    assert.match(after.slice(after.indexOf('</tr>')), new RegExp(`^</tr><tr data-severity="[^"]+" data-tier="${tier}"`), tier);
  }
  assert.equal(rowIds(html).length, 16, '구분 줄은 CVE 행으로 세지 않는다');
  filterIds(d, "activeFilters.search = 'has:kev';");
  assert.match(d.el('cve-table-body').innerHTML, /grp-T0[^]*?<span class="grp-n">3건<\/span>/, '건수는 지금 조건의 결과');
  filterIds(d, "sortField = 'cvss';");
  assert.doesNotMatch(d.el('cve-table-body').innerHTML, /grp-row/, '다른 정렬에서는 구분 줄 없음');
  d.run("sortField = 'tier'; currentPage = 1; filteredCves = allCves.slice().sort(compareCves); renderTable();");
  assert.equal(d.run('listColumns()'), 5, '표를 그리기 전(칸 너비를 모름)에는 전체 칸 수');
});

test('목록 — 알림 시각은 오늘 · 어제면 시각까지, 그 전은 날짜만 (보는 사람의 시간대)', () => {
  const d = dashboard();
  const at = (iso, now) => d.run(`alertTimeText(${JSON.stringify(iso)}, new Date(${JSON.stringify(now)}))`);
  assert.equal(at('2026-09-28T09:55:00Z', '2026-09-28T23:10:00Z'), '오늘 09:55');
  assert.equal(at('2026-09-27T23:59:00Z', '2026-09-28T00:10:00Z'), '어제 23:59');
  assert.equal(at('2026-09-26T09:55:00Z', '2026-09-28T00:10:00Z'), '9. 26.');
  assert.equal(at('2025-12-31T09:55:00Z', '2026-01-02T00:10:00Z'), '25. 12. 31.', '다른 해는 두 자리 연도');
  assert.equal(at('', '2026-09-28T00:10:00Z'), '-');
  assert.equal(at('not-a-date', '2026-09-28T00:10:00Z'), '-');
});

test('영향 버전 한 줄 표기 — 수집 단계 형식을 줄이고, 하한이 없으면 상한만', () => {
  const d = dashboard();
  const short = v => d.run(`ArgusViewModel.shortVersions(${JSON.stringify(v)})`);
  assert.equal(short('0 부터 1.2.3 이전'), '1.2.3 이전', '하한 0 은 적지 않는다');
  assert.equal(short('unspecified 부터 12.2 이전'), '12.2 이전');
  assert.equal(short('1.0 부터 1.4 이하'), '1.0 부터 1.4 이하');
  assert.equal(short('1.0 부터 1.4 이전, 2.0 부터 2.3 이전, 3.0 부터 3.1 이전'), '1.0 부터 1.4 이전 외 2');
  assert.equal(short('16 (단일 버전), 15 (단일 버전), 14 (단일 버전), 13 (단일 버전), 12 (단일 버전)'), '16, 15, 14, 13 외 1', '단일 버전은 넷까지');
  assert.equal(short('1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 (단일 버전)'), '커밋 1da177e', '커밋 해시는 짧게');
  assert.equal(short('모든 버전'), '모든 버전');
  assert.equal(short('정보 없음'), '', '없으면 비운다');
  assert.equal(short('n/a (단일 버전)'), '');
  // 경계가 같은 구간 — 'A 부터 A 이하' 는 그 버전 하나, 'A 부터 A 이전' 은 'A 이전'
  assert.equal(short('9.7.0 부터 9.7.0 이하, 9.6.0 부터 9.6.3 이하'), '9.7.0 외 1');
  assert.equal(short('152.0.7977.82 부터 152.0.7977.82 이전'), '152.0.7977.82 이전');
});

test('조건 칩 · 검색어 이동 · URL — 필터 상태는 검색줄 한 곳에만', () => {
  const d = dashboard();
  d.run(RESET);
  d.run("toggleQueryTerm('has:cisa-kev')");
  assert.equal(d.run('activeFilters.search'), 'has:cisa-kev');
  d.run("toggleQueryTerm('lifecycle:eol')");
  assert.equal(d.run('activeFilters.search'), 'has:cisa-kev lifecycle:eol');
  assert.deepEqual(ids(d.run('filteredCves.map(c => c.id)')), [cve(10)]);
  d.run("toggleQueryTerm('has:cisa-kev')");
  assert.equal(d.run('activeFilters.search'), 'lifecycle:eol');
  d.run("activeFilters.cvssMin = 9.5; activeFilters.vendor = 'acme'; goToQuery('has:exploit no:patch')");
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('activeFilters.cvssMin'), null, '대시보드에서 오면 다른 필터를 푼다');
  assert.deepEqual(ids(d.run('filteredCves.map(c => c.id)')), [cve(3)]);
  assert.match(d.run('history.last'), /view=cves/);
  assert.match(decodeURIComponent(d.run('history.last')).replace(/\+/g, ' '), /q=has:exploit no:patch/);
  d.run("switchView('dashboard')");
  assert.doesNotMatch(d.run('history.last'), /view=|q=/, '대시보드는 기본 화면이라 URL 에 남기지 않는다');
});

test('자동완성 — 필드와 값을 제안한다', () => {
  const d = dashboard();
  const vals = f => d.run(`suggestValues(${JSON.stringify(f)}).map(x => x[0])`);
  assert.ok(vals('has').includes('cisa-kev'));
  assert.ok(vals('corr').includes('kev_eol'));
  assert.ok(vals('no').includes('patch'));
  assert.ok(vals('lifecycle').includes('eol'));
  d.run('buildVendorFilter();');
  assert.ok(vals('vendor').includes('microsoft'));
});

// 상세 본문의 칸 — 위에서부터 이 순서. 칸 하나는 다음 칸이 시작하는 곳까지.
const DETAIL_SECS = ['d-threat', 'd-remedy', 'd-product', 'd-lifecycle', 'd-evidence', 'd-tech', 'd-ai'];
function detailSec(body, id) {
  const start = body.indexOf(`id="${id}"`);
  const ends = DETAIL_SECS.map(x => body.indexOf(`id="${x}"`)).filter(i => i > start);
  return body.slice(start, ends.length ? Math.min(...ends) : body.length);
}
// 가짜 브라우저 기록 — pushState 를 받고, 주소를 실제처럼 바꾼다(뒤로 가기 시험용).
function trackHistory(d) {
  d.run(`history.pushed = [];
    history.pushState = function (state, title, url) { this.pushed.push(String(url)); this.last = String(url); location.href = String(url); };
    history.replaceState = function (state, title, url) { this.last = String(url); location.href = String(url); };`);
}
const edit = (d, changes) => d.run(`(() => { const ch = ${JSON.stringify(changes)};
  for (const [n, o] of Object.entries(ch)) Object.assign(allCves.find(c => c.id === 'CVE-2026-' + String(n).padStart(4, '0')), o); })()`);

test('상세 — 머리글 수치 → 확인된 위협 신호 → 조치 · 영향 제품 → 접어 둔 수명주기 · 근거 · 기술 정보 · AI', () => {
  const d = dashboard();
  d.run(`allCves.find(c => c.id === 'CVE-2026-0001').analysis = { root_cause: 'AI-ROOT-CAUSE-TEXT', mitigation: ['AI-STEP'] };`);
  d.run("showDetail('CVE-2026-0001')");
  const body = d.el('modal-body').innerHTML;
  const order = DETAIL_SECS.map(id => body.indexOf(`id="${id}"`));
  assert.ok(order.every(i => i >= 0), `섹션 모두 있음 ${order}`);
  assert.deepEqual(order, [...order].sort((a, b) => a - b), '확인된 사실 → 조치 · 제품 → 접어 둔 항목 → AI');
  for (const id of ['d-lifecycle', 'd-evidence', 'd-tech', 'd-ai']) {
    assert.match(body, new RegExp(`<details class="d-sec d-fold[^"]*" id="${id}">`), `${id} 는 접어 둔다`);
  }
  assert.doesNotMatch(body, /<details[^>]* open/, '처음에는 모두 접혀 있다');
  const sec = id => detailSec(body, id);
  assert.match(sec('d-threat'), /yes-row ans-exploitation[\s\S]*?CISA KEV 등재/);
  assert.match(sec('d-threat'), /yes-row ans-weaponization[\s\S]*?Metasploit 모듈 1개/);
  assert.match(sec('d-threat'), /yes-row ans-ransomware/);
  assert.match(sec('d-threat'), /yes-row ans-detection[\s\S]*?Sigma/, '탐지 룰도 위협 신호 안에');
  assert.doesNotMatch(sec('d-threat'), /yes-row ans-remediation/, 'OSV 기록이 없으면 확인된 줄에 없다');
  assert.match(sec('d-threat'), /없음 0 · 미확인 3/, '없음 · 미확인은 한 줄로 접는다');
  assert.match(sec('d-threat'), /st-chip st-unknown[^>]*>수정 버전 <b>미확인<\/b>/, 'OSV 기록 없음 → 미확인');
  assert.match(sec('d-threat'), /class="ctx-chip" data-query="has:cisa-kev has:ransom"/, '신호 조합 → 같은 조건 목록');
  assert.match(sec('d-threat'), /ev-row ev-hit[\s\S]*?CISA KEV[\s\S]*?조치 기한 2026-10-10/);
  assert.match(sec('d-threat'), /ev-row ev-miss[\s\S]*?VulnCheck KEV/);
  assert.match(sec('d-threat'), /ev-row ev-unknown[\s\S]*?CISA SSVC[\s\S]*?판정 없음/);
  assert.match(sec('d-threat'), /id="d-ev-detection"[\s\S]*?Sigma/);
  assert.match(sec('d-product'), /Windows 11 version 22H3[\s\S]*?연결 안 됨/, '22H3 은 연결하지 않는다');
  assert.match(sec('d-product'), /제품명 규칙 · 자동 연결/);
  assert.match(sec('d-product'), /microsoft:windows_server_2019/, '정규화 키(CPE 형식) — CPE 원문이 아님을 밝힌다');
  assert.match(sec('d-product'), /<summary>제품 1개 더 보기<\/summary>/, '셋이 넘으면 접는다');
  assert.match(sec('d-lifecycle'), /Microsoft Windows Server[\s\S]*<b>2019<\/b>/);
  assert.match(sec('d-lifecycle'), /사유: 수명주기를 추적하지 않는 제품/);
  assert.match(sec('d-remedy'), /<summary>CISA KEV 필요 조치 · 미 연방기관 기한 2026-10-10<\/summary>/, '누구의 기한인지 이름에 — 등재일 파일 전에는 등재 후 며칠을 모른다');
  assert.match(sec('d-remedy'), /기한은 CISA가 연방기관 지침\(BOD 22-01, 2026-06-10부터 BOD 26-04\)에 따라 정한 미국 연방 민간기관의 조치 기한으로, 다른 기관 · 기업의 의무 기한은 아닙니다/);
  assert.doesNotMatch(sec('d-remedy'), /남음|지남|위 문장은 CISA 원문/, "'N일 지남'은 없고, 원문이 없으면 원문이라고 하지 않는다");
  assert.match(sec('d-evidence'), /EXPLOITATION_CONFIRMED=yes/);
  assert.match(sec('d-evidence'), /RANSOMWARE=yes/);
  assert.match(sec('d-evidence'), /KEV_RANSOMWARE/);
  assert.match(sec('d-evidence'), /endoflife\.date/);
  assert.match(sec('d-evidence'), /신호별 관측 시각은 저장하지 않습니다/);
  assert.match(sec('d-tech'), /원문 파일\(cve-facts\.json\)을 받는 중/, '원문을 아직 못 받았으면 받는 중이라고 적는다');
  assert.match(sec('d-ai'), /AI 작성 · 참고용/);
  assert.match(sec('d-ai'), /AI-ROOT-CAUSE-TEXT/);
  const beforeAi = body.slice(0, body.indexOf('id="d-ai"'));
  assert.doesNotMatch(beforeAi, /AI-ROOT-CAUSE-TEXT|AI-STEP/, 'AI 분석은 사실 · 판정 칸에 섞이지 않는다');
  assert.match(d.el('modal-sev-badge').innerHTML, /Argus · 관측된 악용/, '알림 등급은 Argus 판정으로 표기');
  assert.match(d.el('modal-sev-badge').innerHTML,
               /<details class="tier-menu"><summary class="badge badge-tier tier-T0"[^>]*>Argus · 관측된 악용<span class="tier-caret"[^]*<div class="tier-pop"><b>알림 등급 근거<\/b><ul><li>CISA KEV<\/li><\/ul><small>알림을 보낼지 정하는 기준이며 점수가 아닙니다<\/small><\/div><\/details>/,
               '등급 배지를 누르면 근거');
  assert.equal(d.el('modal-title').textContent, '테스트 취약점 1', '제목 칸에는 제목 글자만');
  assert.equal(d.el('modal-type').hidden, false);
  assert.equal(d.el('modal-type').textContent, 'Out-of-bounds Write', '제목 옆 유형');
  assert.equal(d.el('modal-type').title, 'Out-of-bounds Write — 할당된 메모리 범위 밖에 데이터를 쓰는 결함 (CWE-787)');
  assert.match(d.el('modal-summary').innerHTML, /origin-tag[^>]*>제목 번역 · 요약 원문</,
               '원문 파일 전에는 글자로만 판단 — 한국어 제목은 번역, 영문 요약은 원문');
  const facts = d.el('modal-scores').innerHTML;
  assert.match(facts, /CVSS 3\.1<\/span><span class="vl">9\.8 <span class="band band-Critical">Critical/);
  assert.match(facts, /<div class="fact is-kev" title="실제 악용이 확인돼 CISA KEV 목록에 오른 날"><span class="lbl">CISA KEV 등재<\/span><span class="vl"><span class="vl-unknown">불러오는 중<\/span><\/span><\/div>/, '등재일 파일을 받기 전');
  assert.doesNotMatch(facts, /조치 기한|기한|남음|지남/, '미 연방기관 기한은 머리글에 두지 않는다(조치 칸에서 설명과 함께)');
  assert.match(facts, /<div class="fact is-type" title="Out-of-bounds Write — 할당된 메모리 범위 밖에 데이터를 쓰는 결함 \(CWE-787\)"><span class="lbl">취약점 유형<\/span><span class="vl">Out-of-bounds Write<\/span><span class="sub ty-explain">할당된 메모리 범위 밖에 데이터를 쓰는 결함<\/span><span class="sub ty-ids"><a href="https:\/\/cwe\.mitre\.org\/data\/definitions\/787\.html" target="_blank" rel="noopener noreferrer"[^>]*>CWE-787 ↗<\/a><\/span><\/div>/,
               '유형 칸 — 이름 · 한 줄 풀이 · 번호(MITRE 설명)');
  assert.equal(d.el('detail-origin').textContent, '대시보드', '돌아가기 = 들어오기 전 화면');
});

// 신호마다 '자세히'로 여는 출처 표 칸 — 그 신호 줄 바로 아래(없음 · 미확인이면 칩 줄 아래), 처음에는 닫혀 있다(§6 '화면 개편 5차').
const PANELS = ['exploitation', 'exploit', 'automation', 'ransomware', 'detection'];
test("상세 — '자세히'는 그 신호의 출처 표만 그 줄 바로 아래에, 칩도 같은 칸을 열고, EOL · 수정 버전은 그 칸으로 옮겨 간다", () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0002')");
  const threat = detailSec(d.el('modal-body').innerHTML, 'd-threat');
  assert.doesNotMatch(threat, /d-threat-more|출처별로 보기|rules-details/, "표를 한꺼번에 여는 '출처별로 보기' 묶음은 없다");
  for (const p of PANELS) {
    assert.equal((threat.match(new RegExp(`id="d-panel-${p}"`, 'g')) || []).length, 1, `${p} 칸은 하나`);
    assert.match(threat, new RegExp(`<div class="ev-panel" id="d-panel-${p}" hidden>`), `${p} 칸은 처음에 닫혀 있다`);
  }
  // 확인된 신호 — '자세히' 바로 뒤에 그 신호 칸
  assert.match(threat, /yes-row ans-weaponization">[\s\S]*?<button type="button" class="link-btn ev-toggle" data-panel="exploit" aria-expanded="false" aria-controls="d-panel-exploit">자세히<\/button><\/div><div class="ev-panel" id="d-panel-exploit" hidden><div class="ev-group[^"]*" id="d-ev-exploit">/);
  assert.match(threat, /yes-row ans-detection">[\s\S]*?data-panel="detection"[^>]*>자세히<\/button><\/div><div class="ev-panel" id="d-panel-detection" hidden>[\s\S]*?class="rule-list"/,
               '탐지 룰 칸에는 룰마다 한 줄인 목록');
  assert.match(threat, /id="d-panel-detection"[\s\S]*?class="rule-eng">nuclei<small>점검 템플릿<\/small>[\s\S]*?href="https:\/\/github\.com\/projectdiscovery\/nuclei-templates\/blob\/main\/x\.yaml"[^>]*>원문 ↗/,
               'rules 가 비어 있어도 신호 줄이 보여 주는 엔진(nuclei 템플릿)은 목록에 싣는다');
  assert.match(threat, /yes-row ans-lifecycle">[\s\S]*?<button type="button" class="link-btn is-jump" data-open="lifecycle">수명주기 상세<\/button><\/div>(?!<div class="ev-panel")/);
  // 없음 · 미확인 — 칩을 누르면 칩 줄 아래에서 그 신호 칸
  const line = threat.slice(threat.indexOf('class="st-line"'), threat.indexOf('class="st-panels"'));
  assert.match(line, /없음 1 · 미확인 3/);
  assert.match(line, /<button type="button" data-panel="exploitation" aria-expanded="false" aria-controls="d-panel-exploitation" class="st-chip st-no">실제 악용 <b>보고 없음<\/b><\/button>/);
  assert.match(line, /<button type="button" data-open="remediation" class="st-chip st-unknown" title="[^"]+">수정 버전 <b>미확인<\/b><\/button>/);
  const rest = threat.slice(threat.indexOf('class="st-panels"'));
  assert.deepEqual([...rest.matchAll(/id="d-panel-(\w+)"/g)].map(m => m[1]), ['exploitation', 'automation', 'ransomware']);
  d.run("showDetail('CVE-2026-0008')");
  assert.match(detailSec(d.el('modal-body').innerHTML, 'd-threat'), /yes-row ans-remediation">[\s\S]*?<button type="button" class="link-btn is-jump" data-open="remediation">조치 칸<\/button>/);
  // 엔진을 모르는 '공식 룰 있음'만 있으면 목록 대신 출처 표
  d.run("showDetail('CVE-2026-0009')");
  const official = detailSec(d.el('modal-body').innerHTML, 'd-threat');
  assert.match(official, /id="d-panel-detection" hidden>[\s\S]*?<table class="ev-table">[\s\S]*?공개 룰 색인[\s\S]*?공식 룰 있음/);
  assert.doesNotMatch(official, /class="rule-list"/);
  // 확인된 신호가 없을 때도 칩으로 연다
  d.run("showDetail('CVE-2026-0005')");
  const none = detailSec(d.el('modal-body').innerHTML, 'd-threat');
  assert.match(none, /class="none-card"[\s\S]*?class="st-chips"><button type="button" data-panel="exploitation"[\s\S]*?class="st-panels"><div class="ev-panel" id="d-panel-exploitation" hidden>/);
});

test("상세 — 출처 표 칸은 한 번에 하나만 열리고, 같은 버튼을 다시 누르면 닫힌다", () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0001')");
  // 가짜 DOM 은 HTML 을 읽지 않는다 — 그려진 대로 모두 닫힌 상태에서 시작한다.
  d.run(`for (const t of PANEL_TYPES) byId('d-panel-' + t).hidden = true;`);
  const open = () => PANELS.filter(p => !d.el(`d-panel-${p}`).hidden);
  d.run("togglePanel('exploit', null)");
  assert.deepEqual(open(), ['exploit']);
  d.run("togglePanel('detection', null)");
  assert.deepEqual(open(), ['detection'], '다른 칸을 열면 앞의 칸은 닫힌다');
  d.run("togglePanel('detection', null)");
  assert.deepEqual(open(), [], '같은 칸을 다시 누르면 닫힌다');
  d.run("openEvidence('ransomware'); openEvidence('ransomware')");
  assert.deepEqual(open(), ['ransomware'], '이름으로 열 때는 닫지 않는다');
  d.run("openEvidence('lifecycle')");
  assert.equal(d.el('d-lifecycle').open, true, 'EOL 은 수명주기 상세를 펼친다');
  assert.equal(d.run('PANEL_TYPES.length'), PANELS.length);
});

// 나란히 보기의 오른쪽 칸 — 가짜 DOM 에는 배치가 없어 칸 · 대상의 위치를 정해 준다(칸 위 68 · 고정 막대 아래 118 · 칸 높이 800).
function fakePane(d, target, rect) {
  d.run(`(() => {
    const pane = byId('view-detail');
    pane.classList = { contains: c => c === 'is-pane' };
    pane.scrollTop = 100; pane.clientHeight = 800; pane.scrolled = null;
    pane.getBoundingClientRect = () => ({ top: 68, bottom: 868 });
    pane.contains = () => true;
    pane.querySelector = s => (s === '.detail-bar' ? { getBoundingClientRect: () => ({ bottom: 118 }) } : null);
    pane.scrollTo = o => { pane.scrolled = o; };
    const el = byId(${JSON.stringify(target)});
    el.getBoundingClientRect = () => (${JSON.stringify(rect)});
    el.intoView = false; el.scrollIntoView = () => { el.intoView = true; };
  })()`);
}
test('나란히 보기 — 상세 안에서 옮겨 가기(EOL · 수정 버전 · 출처 간 차이)는 오른쪽 칸만 스크롤하고 창(목록)은 그대로', () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0001')");
  fakePane(d, 'd-remedy', { top: 668, bottom: 900 });
  d.run("openEvidence('remediation')");
  // 대상 위(668 - 68 = 600)를 고정 막대 아래(118 - 68 + 8 = 58)로 — 100 + 542
  assert.equal(d.run("JSON.stringify(byId('view-detail').scrolled)"), JSON.stringify({ top: 642, behavior: 'smooth' }));
  assert.equal(d.run("byId('d-remedy').intoView"), false, 'scrollIntoView 는 칸을 담은 창까지 움직여 쓰지 않는다');
  // 이미 보이는 칸은 옮기지 않는다(nearest) · 칸 아래로 넘치면 보일 만큼만
  fakePane(d, 'd-panel-exploitation', { top: 300, bottom: 600 });
  d.run("byId('d-panel-exploitation').hidden = true; openEvidence('exploitation')");
  assert.equal(d.run("byId('view-detail').scrolled"), null);
  fakePane(d, 'd-panel-exploitation', { top: 700, bottom: 1000 });
  d.run("openEvidence('exploitation')");
  assert.equal(d.run("byId('view-detail').scrolled.top"), 100 + (1000 - 68 - 800));
  // 한 화면 상세는 창이 곧 스크롤 — 예전처럼 scrollIntoView
  d.run("byId('view-detail').classList = { contains: () => false }");
  d.run("openEvidence('remediation')");
  assert.equal(d.run("byId('d-remedy').intoView"), true);
});

test('상세 — 원문(cve-facts) · 원 출처 날짜(cve-evidence)가 있으면 출처와 함께 보인다', () => {
  const d = dashboard();
  d.ctx.__files = {
    facts: { schema: 1, generated_at: '2026-09-27T03:00:00+00:00', facts: {
      'CVE-2026-0001': { o: ['ai', 'ai'], t: 'Windows RCE original title', d: 'Original English description.', a: 'microsoft' },
      'CVE-2026-0003': { o: ['source', 'ai'] } } },
    evidence: { schema: 1, generated_at: '2026-09-27T03:10:00Z', sources: { 'cisa-kev': { catalog_version: '2026.09.26' } },
      actions: ['Apply mitigations per vendor instructions.'],
      kev: { 'CVE-2026-0001': ['2026-09-01', '2026-10-10', 0, ['https://example.com/advisory'], 'Microsoft Windows RCE'] },
      edb: { 'CVE-2026-0002': [['51234', '2026-09-10', '2026-09-11', 1, 'remote', 'windows']] },
      msf: { 'CVE-2026-0001': [['exploit/windows/http/example_rce', 600, '2026-08-30', 'exploit', 1]] } },
  };
  d.run('detailFiles.facts = __files.facts; detailFiles.evidence = __files.evidence;');
  d.run("showDetail('CVE-2026-0001')");
  const body = d.el('modal-body').innerHTML;
  assert.match(d.el('modal-scores').innerHTML, /CISA KEV 등재<\/span><span class="vl">2026-09-01<\/span><span class="sub">26일 전<\/span>/, '등재 후 며칠 — 데이터 기준일(09-27) 기준');
  assert.match(detailSec(body, 'd-remedy'), /<summary>CISA KEV 필요 조치 · 미 연방기관 기한 2026-10-10 <span class="d-muted">\(등재 후 39일\)<\/span><\/summary>/,
               '등재 후 며칠을 줬는지 = CISA 가 본 급한 정도');
  assert.match(detailSec(body, 'd-remedy'), /<p class="d-note">위 문장은 CISA 원문입니다\. 기한은/);
  assert.match(detailSec(body, 'd-threat'), /KEV 등재일 <b>2026-09-01<\/b>/);
  assert.match(detailSec(body, 'd-threat'), /필요 조치 \(CISA 원문\): Apply mitigations per vendor instructions\./);
  assert.match(detailSec(body, 'd-threat'), /exploit\/windows\/http\/example_rce<\/code> · 등급 excellent · check 지원 · 취약점 공개일 2026-08-30/);
  assert.match(detailSec(body, 'd-remedy'), /Apply mitigations per vendor instructions\./);
  assert.match(detailSec(body, 'd-evidence'), /2026-09-01<small>KEV 등재일<\/small>/, '원 출처 날짜 칸');
  assert.match(detailSec(body, 'd-evidence'), /cve-evidence\.json 생성 시각/);
  assert.match(detailSec(body, 'd-tech'), /lang="en">Windows RCE original title<\/span><span class="origin-tag is-source"/);
  assert.match(detailSec(body, 'd-tech'), /CNA \(발급 기관\)<\/span><span class="detail-value">microsoft/);
  assert.match(d.el('modal-summary').innerHTML, />AI 번역·요약</);
  d.run("showDetail('CVE-2026-0002')");
  const b2 = d.el('modal-body').innerHTML;
  assert.match(detailSec(b2, 'd-threat'), /EDB-51234 ↗<\/a> · 공개 2026-09-10 · 검증됨 · remote\/windows/);
  assert.match(detailSec(b2, 'd-evidence'), /2026-09-10<small>Exploit-DB 공개일 \(가장 이른 항목\)<\/small>/);
  assert.match(detailSec(b2, 'd-tech'), /이 CVE는 원문 파일에 아직 없습니다/, '파일은 받았지만 이 CVE 는 없음');
  d.run("showDetail('CVE-2026-0003')");
  assert.match(d.el('modal-summary').innerHTML, />제목 원문 · 요약 AI 번역</);
  d.run('detailFiles.facts = null;');
  d.run("showDetail('CVE-2026-0001')");
  assert.match(detailSec(d.el('modal-body').innerHTML, 'd-tech'), /원문 파일\(cve-facts\.json\)을 받지 못했습니다/);
});

test('출처 간 차이 — 어느 쪽도 지우지 않고 목록 · 상세 · 검색어가 같은 판단', () => {
  const d = dashboard();
  d.run(`Object.assign(allCves.find(c => c.id === 'CVE-2026-0010'), { ssvc_exploitation: 'none', cvss_alt: { '4.0': 6.9, '3.1': 9.9 } });`);
  assert.deepEqual(search(d, 'conflict:exploitation'), [cve(10)]);
  assert.deepEqual(search(d, 'conflict:cvss'), [cve(10)]);
  assert.deepEqual(search(d, 'conflict:any'), [cve(10)]);
  assert.deepEqual(search(d, 'has:conflict'), [cve(10)]);
  filterIds(d, "activeFilters.search = 'conflict:any';");
  assert.match(d.el('cve-table-body').innerHTML, /class="sc-flag"/, '목록 CVSS 칸에 등급 차이 표시');
  d.run("showDetail('CVE-2026-0010')");
  const body = d.el('modal-body').innerHTML;
  const threat = detailSec(body, 'd-threat');
  assert.match(threat, /class="d-flag"><b>출처 간 차이<\/b> KEV에는 있는데 CISA SSVC 판정은 Exploitation: active가 아님 <button type="button" class="link-btn" data-panel="exploitation"/,
               "악용 근거 차이는 접지 않고 보이고, '자세히'는 실제 악용 칸을 연다");
  // 차이의 두 쪽은 관련 신호 칸(실제 악용) 안에 — 칸 밖의 다른 신호 칸에는 넣지 않는다
  const panel = threat.slice(threat.indexOf('id="d-panel-exploitation"'), threat.indexOf('</div><div class="yes-row', threat.indexOf('id="d-panel-exploitation"')));
  assert.match(panel, /출처 간 차이: 악용 근거[\s\S]*?CISA KEV 등재[\s\S]*?CISA SSVC Exploitation: none/);
  assert.match(panel, /data-query="conflict:exploitation"/);
  assert.equal((threat.match(/출처 간 차이: 악용 근거/g) || []).length, 1);
  assert.doesNotMatch(threat, /출처 간 차이: CVSS/, 'CVSS 버전 차이는 위협 신호 칸에 두지 않는다');
  // CVSS 버전 차이 — 머리글 수치 칸과 기술 정보(버전별 점수 · 같은 경우 목록)
  assert.match(d.el('modal-scores').innerHTML, /class="warn"[^>]*>v4\.0은 6\.9 Medium</, '버전별 등급 차이는 머리글 수치에');
  const tech = detailSec(body, 'd-tech');
  assert.match(tech, /CVSS 버전별[\s\S]*?v3\.1 9\.9 · Critical[\s\S]*?v4\.0 6\.9 · Medium|CVSS 버전별[\s\S]*?v4\.0 6\.9 · Medium[\s\S]*?v3\.1 9\.9 · Critical/, '어느 쪽도 지우지 않는다');
  assert.match(tech, /data-query="conflict:cvss"[^>]*>같은 경우 보기 <code>conflict:cvss<\/code>/);
});

test('화면 전환 — 좁은 화면: 상세는 한 화면, URL 의 cve, 닫으면 들어오기 전 화면으로', () => {
  const d = dashboard();
  d.run('innerWidth = 900;');
  d.run("switchView('cves')");
  filterIds(d, "activeFilters.search = 'has:poc';");
  d.run("showDetail('CVE-2026-0003')");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.run('splitOpen'), false, '1200px 미만은 나란히 보기를 쓰지 않는다');
  assert.match(d.run('history.last'), /cve=CVE-2026-0003/);
  assert.match(decodeURIComponent(d.run('history.last')), /view=cves&q=has:poc/, '목록 맥락은 URL 에 남긴다');
  assert.doesNotMatch(d.run('history.last'), /full=1/, 'full 은 넓은 화면에서만');
  assert.deepEqual(JSON.parse(d.run("localStorage.getItem('argus-recent')")).map(x => x.id), ['CVE-2026-0003'],
                   '연 상세는 이 브라우저의 최근 본 CVE 에 남는다');
  assert.equal(d.el('detail-origin').textContent, 'CVE 목록');
  d.run('closeModal()');
  assert.equal(d.run('currentView'), 'cves');
  assert.doesNotMatch(d.run('history.last'), /cve=/);
  d.run("switchView('dashboard'); openCve('CVE-2026-0002')");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('detail-pos').textContent, '', '대시보드에서 하나만 열면 이전 · 다음 없음');
  d.run('closeModal()');
  assert.equal(d.run('currentView'), 'dashboard', '대시보드에서 열었으면 대시보드로');
  assert.doesNotMatch(d.run('history.last'), /view=|cve=/);
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Akev&cve=CVE-2026-0004'; applyUrlState(); openFromUrl();");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0004');
  assert.equal(d.run('activeFilters.search'), 'has:kev');
  d.run('closeModal()');
  assert.equal(d.run('currentView'), 'cves');
  d.run("location.href = 'https://example.test/cve.html?cve=CVE-2026-0003'; applyUrlState(); openFromUrl();");
  assert.equal(d.el('detail-pos').textContent, '', '공유 링크로 연 상세는 이전 · 다음 없음');
  assert.equal(d.el('detail-bottom').hidden, true, '넘길 CVE 가 없으면 아래 막대도 감춘다');
  d.run("location.href = 'https://example.test/cve.html?cve=CVE-1999-0001'; applyUrlState(); openFromUrl();");
  assert.match(d.el('modal-body').innerHTML, /추적 목록\(최근 90일/, '추적 밖 CVE 는 없다고 알린다');
});

test('나란히 보기 — 넓은 화면의 목록에서 상세를 오른쪽에 열고, 행을 바꿔도 기록을 늘리지 않는다', () => {
  const d = dashboard();
  trackHistory(d);
  d.run("goToQuery('has:poc')");
  const base = d.run('history.pushed.length');
  assert.deepEqual(d.run('filteredCves.map(c => c.id)'), [cve(14), cve(3)], '알림 등급 순');
  d.run("showDetail('CVE-2026-0003')");
  assert.equal(d.run('currentView'), 'cves', '목록은 그대로');
  assert.equal(d.run('splitOpen'), true);
  assert.equal(d.run('history.pushed.length'), base + 1, '처음 열 때만 기록');
  assert.match(decodeURIComponent(d.run('location.href')), /view=cves&q=has:poc&cve=CVE-2026-0003$/);
  assert.equal(d.el('detail-pos').textContent, '2 / 2');
  assert.equal(d.run('document.documentElement.dataset.nav'), 'rail', '1680px 미만에서는 메뉴를 아이콘으로 접는다');
  d.run('stepDetail(-1)');
  assert.equal(d.run('detailId'), cve(14));
  d.run("showDetail('CVE-2026-0003')");
  assert.equal(d.run('history.pushed.length'), base + 1, '이전 · 다음 · 다른 행은 기록을 늘리지 않는다');
  d.run('openFull()');
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.run('splitOpen'), false);
  assert.match(d.run('location.href'), /full=1/, '새로 고쳐도 한 화면으로');
  assert.equal(d.el('detail-pos').textContent, '2 / 2', '한 화면에서도 목록 순서로 이전 · 다음');
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Apoc&cve=CVE-2026-0003'; onPopState({ state: null });");
  assert.equal(d.run('splitOpen'), true, '뒤로 가기로 나란히 보기에 돌아온다');
  d.run('detailPushed = false; closeModal()');
  assert.equal(d.run('splitOpen'), false);
  assert.equal(d.run('currentView'), 'cves');
  assert.doesNotMatch(d.run('location.href'), /cve=/);
  assert.equal(d.run('document.documentElement.dataset.nav'), undefined, '닫으면 메뉴를 다시 편다');
  d.run("localStorage.setItem('argus-nav', 'open'); showDetail('CVE-2026-0003')");
  assert.equal(d.run('document.documentElement.dataset.nav'), undefined, '사용자가 고른 메뉴 상태가 먼저');
});

test('조건 줄 — 조건 칩은 늘 모두 보이고(접지 않음) 칩에는 이름만, 전체 건수는 설명에', () => {
  const d = dashboard();
  d.run('renderQuickChips()');
  const quick = d.el('quick-chips').innerHTML;
  assert.equal((quick.match(/class="q-chip /g) || []).length, 10, '조건 칩 10개 모두');
  assert.doesNotMatch(quick, /q-more|is-extra|접기|조건 \+/, "'조건 +N' 으로 접지 않는다");
  assert.doesNotMatch(quick, /<b>/, '칩에는 숫자를 적지 않는다');
  assert.match(quick, /data-term="has:kev"[^>]*title="[^"]*\(검색어 has:kev, 전체 3건\)">\s*<i><\/i>악용 근거<\/button>/, '전체 건수는 마우스를 올리면 보이는 설명에');
  const src = d.el('source-chips').innerHTML;
  assert.doesNotMatch(src, /<b>/, '필터 안 출처별 칩도 이름만');
  assert.match(src, /data-term="has:vulncheck-kev"[^>]*전체 \d+건\)">/);
  // '필터' 숫자 = 필터 안에 들어 있는 조건만 — 검색어와 조건 줄에 늘 보이는 CVSS · EPSS 는 세지 않는다(나란히 보기도 같다)
  d.run("activeFilters.cvssMin = 7; activeFilters.vendor = 'Microsoft'; renderChips();");
  assert.equal(d.el('filter-count').textContent, '1');
  d.run("switchView('cves'); showDetail('CVE-2026-0003'); renderChips();");
  assert.equal(d.run('splitOpen'), true);
  assert.equal(d.el('filter-count').textContent, '1', '나란히 보기에서도 조건 줄은 같다');
});

test('최근 본 CVE — 상세를 열면 이 브라우저에만 10건까지, 빈 검색창을 누르면 목록, 본 CVE 는 목록에서 흐리게', () => {
  const d = dashboard();
  const stored = () => JSON.parse(d.run("localStorage.getItem('argus-recent') || '[]'")).map(x => x.id);
  for (const n of [3, 1, 2, 3]) d.run(`showDetail('${cve(n)}')`);
  assert.deepEqual(stored(), [cve(3), cve(2), cve(1)], '최근 것이 먼저, 같은 CVE 는 한 번');
  d.run(`rememberViewed('x"><img src=x>'); rememberViewed('')`);
  assert.deepEqual(stored(), [cve(3), cve(2), cve(1)], 'CVE ID 가 아니면 남기지 않는다');
  // 빈 검색창을 누르면 — ID · 심각도 · 본 지 얼마 · 제목 · 유형
  d.run("byId('search-input').value = ''; renderViewed();");
  const box = d.el('search-recent');
  assert.equal(box.hidden, false);
  assert.equal(d.el('search-pop').hidden, false);
  assert.match(box.innerHTML, /<b>최근 본 CVE<\/b><button type="button" class="sr-clear">지우기<\/button>/);
  assert.deepEqual([...box.innerHTML.matchAll(/<span class="cve-id">([^<]+)<\/span>/g)].map(m => m[1]), [cve(3), cve(2), cve(1)]);
  assert.match(box.innerHTML, /CVE-2026-0001<\/span><span class="badge badge-sev sev-Critical">Critical<\/span><span class="sr-ago">방금<\/span>/);
  assert.match(box.innerHTML, /<span class="sr-l2">테스트 취약점 1 · Out-of-bounds Write<\/span>/, '제목 · 유형');
  assert.match(box.innerHTML, /이 브라우저에만 저장합니다 · 최대 10건/);
  d.run("byId('search-input').value = 'has'; renderViewed();");
  assert.equal(d.el('search-recent').hidden, true, '글자가 있으면 검색 제안 · 미리보기');
  // 누르면 상세 — 이전 · 다음은 그 목록 안에서
  d.run("byId('search-input').value = ''; renderViewed(); openViewedItem(1);");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('modal-id').textContent, cve(2));
  assert.equal(d.el('detail-pos').textContent, '최근 본 CVE · 2 / 3');
  // 목록에서는 ID 를 흐리게
  d.run("switchView('cves')");
  filterIds(d, '');
  const html = d.el('cve-table-body').innerHTML;
  assert.match(html, /<span class="cve-id is-seen" title="최근에 본 CVE">CVE-2026-0002<\/span>/);
  assert.match(html, /<span class="cve-id">CVE-2026-0004<\/span>/, '보지 않은 CVE 는 그대로');
  // 10건까지 · 추적 목록에서 빠진 CVE 는 목록에 싣지 않는다
  for (let n = 4; n <= 16; n++) d.run(`rememberViewed('${cve(n)}')`);
  assert.equal(stored().length, 10);
  assert.equal(stored()[0], cve(16));
  d.run(`localStorage.setItem('argus-recent', JSON.stringify([{ id: 'CVE-1999-0001', at: Date.now() }, { id: '${cve(5)}', at: Date.now() - 3 * 36e5 }, { id: 'bad', at: 1 }]))`);
  d.run("byId('search-input').value = ''; renderViewed();");
  assert.deepEqual([...d.el('search-recent').innerHTML.matchAll(/<span class="cve-id">([^<]+)<\/span>/g)].map(m => m[1]), [cve(5)]);
  assert.match(d.el('search-recent').innerHTML, /<span class="sr-ago">3시간 전<\/span>/);
  // 지우기
  d.run('clearViewed(); renderViewed();');
  assert.equal(d.run("localStorage.getItem('argus-recent')"), null);
  assert.match(d.el('search-recent').innerHTML, /최근 본 CVE가 없습니다\. 상세를 열면 여기에 10건까지 남습니다\./);
  // 저장이 막혀도 상세 · 목록은 그대로
  d.run("localStorage.getItem = () => { throw new Error('blocked'); }; localStorage.setItem = () => { throw new Error('blocked'); };");
  d.run(`showDetail('${cve(1)}')`);
  assert.equal(d.el('modal-id').textContent, cve(1));
  assert.equal(d.run('viewedList().length'), 0, '읽지 못하면 빈 목록');
  assert.deepEqual(['30000', '300000', '10800000', '172800000'].map(ms => d.run(`agoText(Date.now() - ${ms}, Date.now())`)),
                   ['방금', '5분 전', '3시간 전', '2일 전']);
});

test('방문 기록 — 대시보드 숫자 · 제품 순위 · 화면 이동은 기록을 남기고, 뒤로 가기는 주소대로 화면을 되돌린다', () => {
  const d = dashboard();
  trackHistory(d);
  d.run("goToQuery('has:cisa-kev')");
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('history.pushed.length'), 1);
  assert.match(decodeURIComponent(d.run('history.pushed[0]')), /view=cves&q=has:cisa-kev/);
  d.run("switchView('dashboard', { push: true })");
  assert.equal(d.run('history.pushed.length'), 2);
  d.run("filterByProduct('Java SE')");
  assert.equal(d.run('history.pushed.length'), 3, '영향 제품 순위도 기록을 남긴다');
  assert.equal(d.run('activeFilters.product'), 'java se');
  d.run("location.href = 'https://example.test/cve.html'; onPopState({ state: { scroll: 0 } });");
  assert.equal(d.run('currentView'), 'dashboard');
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Apoc'; onPopState({ state: { scroll: 120 } });");
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('activeFilters.search'), 'has:poc');
  d.run("location.href = 'https://example.test/cve.html?view=cves&q=has%3Apoc&cve=CVE-2026-0003&full=1'; onPopState({ state: null });");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.run('splitOpen'), false);
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0003');
});

test('검색 미리보기 — 목록 밖에서는 화면을 옮기지 않고 결과를 보여 주며, Enter 를 눌러야 목록으로 간다', () => {
  const d = dashboard();
  trackHistory(d);
  d.run("renderSearchPreview('windows')");
  assert.equal(d.run('currentView'), 'dashboard', '입력만으로 화면을 옮기지 않는다');
  const ids = JSON.parse(JSON.stringify(d.run('previewState.ids')));
  assert.deepEqual([...ids].sort(), search(d, 'windows'), '미리보기 건수 = 그 검색어로 연 목록');
  const box = d.el('search-preview').innerHTML;
  assert.match(box, new RegExp(`CVE ${ids.length}건`));
  assert.match(box, new RegExp(`목록에서 ${ids.length}건 보기`));
  assert.equal((box.match(/class="sp-item"/g) || []).length, Math.min(5, ids.length));
  assert.equal(d.run('history.pushed.length'), 0, '미리보기는 기록을 남기지 않는다');
  d.run('openPreviewItem(0)');
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('detail-pos').textContent, `검색 "windows" · 1 / ${ids.length}`, '이전 · 다음은 검색 결과 순서');
  d.run("switchView('dashboard')");
  d.el('search-input').value = 'has:poc';
  d.run('submitSearch()');
  assert.equal(d.run('currentView'), 'cves');
  assert.equal(d.run('activeFilters.search'), 'has:poc');
  assert.match(decodeURIComponent(d.run('history.pushed[history.pushed.length - 1]')), /view=cves&q=has:poc/, 'Enter 는 기록을 남긴다');
  d.run("switchView('dashboard')");
  d.el('search-input').value = 'cve-2026-0003';
  d.run('submitSearch()');
  assert.equal(d.run('currentView'), 'detail', 'CVE ID 를 정확히 넣으면 그 상세');
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0003');
  d.run("switchView('cves'); renderSearchPreview('windows')");
  assert.equal(d.el('search-preview').hidden, true, '목록 화면에서는 입력하는 대로 목록이 거른다');
});

test('새 검색어 — sev · published · kev · due (기준일 = 데이터를 만든 시각의 UTC 날짜, Nd 는 기준일 포함 N일)', () => {
  const d = dashboard();
  edit(d, { 2: { published: '2026-09-21', kev_due_date: '2026-09-28' }, 3: { published: '2026-09-20' }, 4: { published: '2026-09-27' },
            5: { published: '2026-09-28' }, 10: { kev_due_date: '2026-09-29' }, 1: { kev_due_date: '2026-09-30' } });
  assert.equal(d.run('refDay()'), '2026-09-27');
  assert.deepEqual(search(d, 'sev:critical'), [cve(1), cve(7), cve(10)]);
  assert.deepEqual(search(d, 'sev:none'), [cve(5)], 'CVSS 점수 없음');
  assert.deepEqual(search(d, 'published:7d'), [cve(2), cve(4)], '09-21 ~ 09-27, 기준일 뒤 날짜는 넣지 않는다');
  assert.deepEqual(search(d, 'published:1d'), [cve(4)], '기준일 당일');
  assert.deepEqual(search(d, 'published:7'), [], '단위가 없으면 아무것도 통과시키지 않는다');
  assert.deepEqual(search(d, 'due:3d'), [cve(10)], 'CISA KEV 인 것만, 기준일부터 3일 안(09-27 ~ 09-29)');
  assert.deepEqual(search(d, 'kev:7d'), [], '등재일 파일(cve-evidence.json) 전에는 셀 수 없다');
  d.run(`detailFiles.evidence = { schema: 1, kev: { 'CVE-2026-0001': ['2026-09-21', '2026-10-10'], 'CVE-2026-0010': ['2026-09-20', '2026-09-29'] } };`);
  assert.deepEqual(search(d, 'kev:7d'), [cve(1)], 'CISA KEV 등재일 기준');
  assert.deepEqual(search(d, 'kev:30d'), [cve(1), cve(10)]);
});

test('대시보드 최근 동향 — 카드 숫자 = 그 검색어로 연 목록 건수, KPI 아래 변화도 같은 검색어로 센다', () => {
  const d = dashboard();
  edit(d, { 2: { published: '2026-09-21' }, 4: { published: '2026-09-27' }, 5: { published: '2026-09-25' },
            15: { severity: 'Critical', cvss: 9.1 }, 10: { kev_due_date: '2026-09-27' } });
  d.run('renderDashboard()');
  assert.match(d.el('dash-today').innerHTML, /KEV 신규 등재[\s\S]*?등재일 정보를 받는 중/, '등재일 파일 전');
  assert.match(d.el('dash-kpis').innerHTML, /id="stat-kev">2<\/span>\s*<span class="kpi-sub">악용 근거 전체 3건</, '변화를 셀 수 없으면 출처 건수');
  d.run(`detailFiles.evidence = { schema: 1, kev: { 'CVE-2026-0001': ['2026-09-22', '2026-10-10'], 'CVE-2026-0010': ['2026-09-26', '2026-09-27'] } };
    renderDashboard();`);
  const today = d.el('dash-today').innerHTML;
  const cards = [...today.matchAll(/data-card="(\w+)"[\s\S]*?class="t-n" data-query="([^"]+)"[^>]*>(\d+)</g)]
    .map(m => ({ key: m[1], q: unesc(m[2]), n: Number(m[3]) }));
  assert.deepEqual(cards.map(c => c.key), ['kev', 'crit', 'exp']);
  for (const c of cards) assert.equal(search(d, c.q).length, c.n, `${c.key}: ${c.q}`);
  assert.deepEqual(cards.map(c => c.n), [2, 1, 1]);
  const card = key => today.slice(today.indexOf(`data-card="${key}"`), today.indexOf('</article>', today.indexOf(`data-card="${key}"`)));
  assert.deepEqual([...card('kev').matchAll(/data-cve="([^"]+)"/g)].map(m => m[1]), [cve(10), cve(1)], '등재일 최신순');
  assert.match(card('kev'), /class="t-link" data-query="due:3d"[^>]*>미 연방기관 기한 3일 안 1건</, '누구의 기한인지 이름에, 빨간 강조 없이');
  assert.match(card('kev'), /<span class="t-right"><span class="t-key">등재 09-26<\/span><\/span>/, '줄마다 등재일만');
  assert.doesNotMatch(card('kev'), /is-hot|t-due|기한 오늘|기한 지남/);
  assert.match(card('kev'), />2건 모두 보기 →</);
  assert.match(card('crit'), /알림·갱신 5건 중/);
  assert.match(card('exp'), /최근 7일 공개 3건 중/);
  assert.match(card('exp'), /data-cve="CVE-2026-0002"/);
  d.run("openCveFrom('CVE-2026-0001', todayLists.kev)");
  assert.equal(d.run('currentView'), 'detail');
  assert.equal(d.el('detail-pos').textContent, 'KEV 신규 등재 · 2 / 2', '이전 · 다음은 그 카드의 순서');
  assert.equal(d.el('detail-origin').textContent, '대시보드');
  const kpis = d.el('dash-kpis').innerHTML;
  assert.match(kpis, /id="stat-total">16<\/span>\s*<span class="kpi-sub"><b class="kpi-up">\+3<\/b> 최근 7일 공개/);
  assert.equal(search(d, 'published:7d').length, 3);
  assert.match(kpis, /id="stat-kev">2<\/span>\s*<span class="kpi-sub"><b class="kpi-up">\+2<\/b> 최근 7일 등재/);
  assert.equal(search(d, 'kev:7d').length, 2);
  assert.match(kpis, /id="stat-24h">5<\/span>\s*<span class="kpi-sub">Critical 1 · KEV 0</);
  assert.match(kpis, /id="stat-ai">1<\/span>\s*<span class="kpi-sub"><b class="kpi-up">\+1<\/b> 최근 7일 공개/);
  assert.equal(search(d, 'published:7d has:ai').length, 1);
  d.run('detailFiles.evidence = null; renderDashboard();');
  assert.match(d.el('dash-today').innerHTML, /받지 못해 셀 수 없습니다[\s\S]*?data-query="has:cisa-kev"[^>]*>CISA KEV 전체 보기/,
               '등재일 파일을 못 받으면 0 대신 셀 수 없다고');
});

test('테마 — 시스템 → 라이트 → 다크 → 시스템, 고른 값은 저장', () => {
  const d = dashboard();
  const theme = () => d.run('currentTheme()');
  assert.equal(theme(), 'system');
  d.run('cycleTheme()');
  assert.equal(theme(), 'light');
  assert.equal(d.run("localStorage.getItem('argus-theme')"), 'light');
  assert.equal(d.el('theme-toggle').title, '테마: 라이트 (누르면 다크)');
  d.run('cycleTheme()');
  assert.equal(theme(), 'dark');
  d.run('cycleTheme()');
  assert.equal(theme(), 'system');
  assert.equal(d.run("localStorage.getItem('argus-theme')"), null);
});

test('상세 — 미확인의 사유 (점수 없음 · 추적 밖 제품 · endoflife.date 미제공 · 수정 기록 없음)', () => {
  const d = dashboard();
  d.run("showDetail('CVE-2026-0005')");
  assert.match(d.el('modal-scores').innerHTML, /점수 없음<\/span><\/span><span class="sub">0점이 아니라 미확인/);
  const b5 = d.el('modal-body').innerHTML;
  assert.match(b5, /class="none-card"[\s\S]*?확인된 위협 신호 없음[\s\S]*?7개 항목 중 없음 3 · 미확인 4/);
  assert.match(b5, /st-chip st-unknown" title="수명주기를 추적하지 않는 제품이 있음[^"]*">EOL <b>미확인<\/b>/, '미확인은 사유를 붙인다');
  assert.doesNotMatch(d.el('modal-signals').innerHTML, /c-none|lc-none/, '머리글에는 확인된 것만');
  d.run("showDetail('CVE-2026-0012')");
  assert.match(d.el('modal-body').innerHTML, /lc-unresolved[\s\S]*OpenSSH[\s\S]*사유: endoflife\.date에 없는 제품/);
  d.run("showDetail('CVE-2026-0003')");
  const b3 = d.el('modal-body').innerHTML;
  assert.match(b3, /st-chip st-no">수정 버전 <b>기록 없음<\/b>/);
  assert.match(detailSec(b3, 'd-remedy'), /OSV에 영향 패키지는 있지만 수정 버전 기록이 없습니다/);
});

// 제품 수명주기 화면 — endoflife.date 전체 목록(fixture: tests/fixtures/lifecycle_catalog_sample.json, 기준일 TODAY).
function lifecyclePage(catalog = readJson('lifecycle_catalog_sample.json')) {
  const d = dashboard();
  d.ctx.__cat = catalog;
  d.run('setLifecycleCatalog(__cat);');
  const view = code => {
    d.run(`Object.assign(LC_PAGE, { q: '', soon: false, product: null, auto: null }); LC_PAGE.open.clear(); ${code || ''}; renderLifecycleView();`);
    return d.el('lc-cats').innerHTML;
  };
  return { d, view };
}
const picks = html => [...html.matchAll(/class="lc-pick" data-slug="([^"]+)"/g)].map(m => m[1]);
const catsOf = html => [...html.matchAll(/<section class="lc-cat" data-cat="([^"]+)"/g)].map(m => m[1]);
const rowsOf = html => [...html.matchAll(/<tr( class="([^"]*)")?( hidden)?><td data-label="버전"><b>([^<]+)<\/b>/g)]
  .map(m => ({ cycle: m[4], hidden: !!m[3], cls: m[2] || '' }));

test('제품 수명주기 — 분류는 처음에 접혀 있고, 제품 수 · 90일 안에 EOL 제품 수만 보인다', () => {
  const { d, view } = lifecyclePage();
  const html = view();
  assert.deepEqual(catsOf(html), ['os', 'server-app', 'database', 'framework'], '정한 순서 · 제품이 있는 분류만');
  assert.doesNotMatch(html, /lc-grid/, '처음에는 모두 접힘');
  assert.equal((html.match(/aria-expanded="false"/g) || []).length, 4);
  assert.match(html, /data-cat="server-app"[\s\S]*?서버 애플리케이션[\s\S]*?제품 <b>2<\/b>[\s\S]*?90일 안에 EOL <b>1<\/b>/);
  assert.doesNotMatch(html.slice(html.indexOf('data-cat="os"'), html.indexOf('data-cat="server-app"')), /90일 안에 EOL/, '없으면 적지 않는다');
  // 90일 안에 EOL = 기준일 다음 날부터 90일 안(오늘 EOL 은 이미 EOL) — lifecycle.js 로 직접 센 값과 같다
  const LCJ = require('../docs/js/lifecycle.js');
  const cat = readJson('lifecycle_catalog_sample.json');
  const soon = new Set(cat.releases.filter(r => LCJ.eolWithin(r, '<=', 90, TODAY)).map(r => r.product_slug));
  assert.deepEqual([...soon], ['kubernetes']);
  assert.equal(d.el('lc-soon-n').textContent, String(soon.size));
  assert.match(d.el('lc-asof').innerHTML, /endoflife\.date 제품 <b>7<\/b>개 · 버전 <b>23<\/b>개의 지원 일정 · 상태 기준일 2026-09-27/);
  assert.match(d.el('lc-meta').textContent, /매일 확인하고 바뀐 날만 새로 씁니다 · 마지막 변경 2026-09-27 12:00 UTC/);
  assert.equal(d.el('lc-count').innerHTML, '', '거르지 않으면 건수 줄이 없다');
  assert.doesNotMatch(html + d.el('lc-asof').innerHTML, /CVE|data-query|release:/, 'CVE 연결은 이 화면에 싣지 않는다');
});

test('제품 수명주기 — 분류를 펴면 이름 격자, 제품을 누르면 지원 중인 버전 먼저 · 지난 버전은 더 보기', () => {
  const { view } = lifecyclePage();
  let html = view("LC_PAGE.open.add('server-app')");
  assert.deepEqual(picks(html), ['kubernetes', 'nginx'], '이름순(대소문자 무시)');
  assert.match(html, /data-slug="kubernetes" title="Kubernetes — 90일 안에 EOL: 1\.34 2026-10-27 \(D-30\)"[^>]*>[\s\S]*?<span class="lc-dday">D-30<\/span>/);
  assert.doesNotMatch(html, /lc-detail/, '제품을 누르기 전에는 표가 없다');
  html = view("LC_PAGE.open.add('server-app'); LC_PAGE.product = 'kubernetes'");
  assert.match(html, /data-slug="kubernetes"[^>]*aria-expanded="true" aria-controls="lc-d-kubernetes"/);
  assert.deepEqual(rowsOf(html), [{ cycle: '1.37', hidden: false, cls: '' }, { cycle: '1.34', hidden: false, cls: 'is-soon' },
                                  { cycle: '1.33', hidden: true, cls: 'lc-extra' }]);
  assert.match(html, /data-kind="지난 버전">지난 버전 1개 더 보기</);
  assert.match(html, /<td data-label="EOL" class="lc-eol">2026-10-27<span class="lc-dday" title="EOL까지 30일">D-30<\/span>/);
  assert.match(html, /lc-UNKNOWN[\s\S]*?<span class="lc-phase">제조사 단계: Maintenance Support<\/span>/, 'UNKNOWN 은 제조사 단계 이름을 함께');
  assert.match(html, /<th>버전<\/th><th>상태<\/th><th>출시<\/th><th title="제조사의 'Active Support' 단계가 끝나는 날">기본 지원 종료<\/th><th title="[^"]*">EOL<\/th><th>최신 버전<\/th>/,
               '제품에 있는 단계만 칸으로(Kubernetes 는 확장 지원 없음)');
  assert.doesNotMatch(html, /보안 지원 종료|릴리스/);
  assert.match(html, /별칭 k8s/);
  assert.match(html, /기본 지원 종료 = 'Active Support' 단계의 끝 · EOL = 'Maintenance Support' 단계의 끝<br>출처: <a href="https:\/\/endoflife\.date\/kubernetes"/);
  // 단계가 셋인 제품 · 라벨의 겹치는 앞부분 · 확장 지원 중인 버전은 '지난 버전'이 아니다
  html = view("LC_PAGE.open.add('os'); LC_PAGE.product = 'debian'");
  assert.match(html, /<th title="[^"]*">기본 지원 종료<\/th><th title="[^"]*">EOL<\/th><th title="[^"]*">확장 지원 종료<\/th>/);
  assert.match(html, /<b>13<\/b><span class="lc-cycle-label">\(Trixie\)<\/span>/);
  assert.deepEqual(rowsOf(html).map(r => r.hidden), [false, false, false, false], 'EXTENDED 는 지원 중');
  assert.doesNotMatch(html, /더 보기/);
  // 지원 중인 버전이 없으면 가장 최근 버전 하나만
  const cat = readJson('lifecycle_catalog_sample.json');
  cat.releases = cat.releases.map(r => (r.product_slug === 'redis' ? Object.assign({}, r, { eol_date: '2020-01-01', eol_reached: true }) : r));
  const old = lifecyclePage(cat);
  html = old.view("LC_PAGE.open.add('database'); LC_PAGE.product = 'redis'");
  assert.deepEqual(rowsOf(html).map(r => r.hidden), [false, true, true]);
  assert.match(html, /data-slug="redis"[^>]*title="Redis — 모든 버전이 EOL"[\s\S]*?<span class="lc-gone">전체 EOL<\/span>/);
});

test('제품 수명주기 — 검색: 이름 · 별칭 · 제조사 태그(통째로) · 버전, 맞는 분류만 펼침', () => {
  const { d, view } = lifecyclePage();
  let html = view("LC_PAGE.q = 'k8s'");
  assert.deepEqual(catsOf(html), ['server-app']);
  assert.deepEqual(picks(html), ['kubernetes']);
  assert.match(html, /<span class="lc-pick-sub">별칭 k8s<\/span>/);
  assert.match(html, /class="lc-cat-head is-static"/, '거르는 동안 분류는 접을 수 없이 펼쳐 둔다');
  assert.match(html, /id="lc-d-kubernetes"/, '결과가 하나면 표를 연다');
  assert.equal(d.el('lc-count').innerHTML, '제품 <b>1</b>개 · 분류 <b>1</b>개');
  html = view("LC_PAGE.q = 'SERVER'");
  assert.deepEqual(picks(html), ['windows-server']);
  assert.match(html, /Microsoft Windows <mark>Server<\/mark>/, '대소문자 무시 · 맞은 곳 표시');
  html = view("LC_PAGE.q = 'oracle'");
  assert.deepEqual(picks(html), ['mysql']);
  assert.match(html, /<span class="lc-pick-sub">태그 oracle<\/span>/);
  assert.match(view("LC_PAGE.q = 'orac'"), /찾는 제품이 없습니다/, '태그는 통째로 같을 때만');
  html = view("LC_PAGE.q = 'debian 12'");
  assert.match(html, /<span class="lc-pick-sub">버전 12<\/span>/);
  assert.deepEqual(rowsOf(html).filter(r => /is-hit/.test(r.cls)).map(r => r.cycle), ['12']);
  html = view("LC_PAGE.q = 'bookworm'");
  assert.deepEqual(picks(html), ['debian'], '코드명');
  html = view("LC_PAGE.q = '22'");
  assert.deepEqual(picks(html), ['nodejs'], '숫자는 사이클 앞부분만 — 2022 같은 날짜에 걸리지 않는다');
  html = view("LC_PAGE.q = '8'");
  assert.deepEqual(picks(html).sort(), ['mysql', 'redis'], '8 → 8.4 · 8.0 · 8.10 · 8.8 (숫자는 k8s 같은 이름 · 별칭에 걸지 않는다)');
  // 같은 검색어에서 닫은 표는 다시 열지 않는다(공백만 다른 검색어 포함)
  d.run("Object.assign(LC_PAGE, { q: 'k8s', soon: false, product: null, auto: 'k8s' }); renderLifecycleView();");
  assert.doesNotMatch(d.el('lc-cats').innerHTML, /id="lc-d-kubernetes"/);
});

test('제품 수명주기 — 90일 안에 EOL: 해당 제품만 남은 날 순으로, 칸마다 가장 가까운 버전', () => {
  const { d, view } = lifecyclePage();
  const html = view('LC_PAGE.soon = true');
  assert.deepEqual(catsOf(html), ['server-app']);
  assert.deepEqual(picks(html), ['kubernetes']);
  assert.match(html, /<span class="lc-pick-sub">1\.34 · 2026-10-27<\/span>/);
  assert.match(html, /90일 안에 EOL <b>1<\/b> \/ 2/);
  assert.equal(d.el('lc-count').innerHTML, '제품 <b>1</b>개 · 버전 <b>1</b>개 · 기준일 2026-09-27');
  // 기준일이 바뀌면 다시 센다 — 오늘 EOL 인 버전은 이미 EOL 이라 빠지고, 90일 안으로 들어온 버전이 생긴다
  d.run("lcToday = '2026-10-26';");
  assert.match(view('LC_PAGE.soon = true'), /data-slug="kubernetes"[\s\S]*?<span class="lc-dday">D-1<\/span>/);
  d.run("lcToday = '2026-10-27';");
  const later = view('LC_PAGE.soon = true');
  assert.deepEqual(picks(later), ['windows-server']);
  assert.match(later, /<span class="lc-pick-sub">Windows Server 2016 \(LTSC\) · 2027-01-12<\/span><\/span><span class="lc-dday">D-77<\/span>/);
});

test('제품 수명주기 — 목록을 못 받으면 안내와 다시 불러오기, 모르는 분류는 뒤에, 값은 이스케이프', () => {
  const d = dashboard();
  d.run('renderLifecycleView();');
  assert.match(d.el('lc-cats').innerHTML, /불러오지 못했습니다[\s\S]*data-lc-retry/, '브라우저가 아니면(fetch 없음) 실패로');
  const cat = readJson('lifecycle_catalog_sample.json');
  cat.products.zzz = Object.assign({}, cat.products.nginx, { label: '<img src=x onerror=alert(1)>', category: 'robots' });
  cat.releases.push({ product_slug: 'zzz', cycle: '1<b>', eol_reached: false });
  const { view } = lifecyclePage(cat);
  const html = view("LC_PAGE.open.add('robots'); LC_PAGE.product = 'zzz'");
  assert.deepEqual(catsOf(html), ['os', 'server-app', 'database', 'framework', 'robots']);
  assert.doesNotMatch(html, /<img|<b>1<b>/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /<b>1&lt;b&gt;<\/b>/);
  const bad = lifecyclePage({ schema: 2, products: {}, releases: [] });
  assert.match(bad.view(), /불러오지 못했습니다/, '모르는 스키마는 읽지 않는다');
});

test('내보내기 스키마는 그대로 — 파생 값을 CVE 행에 섞지 않는다', () => {
  const d = dashboard();
  filterIds(d, '');
  d.run('filteredCves.forEach(cveContext)');
  const json = d.run('JSON.stringify(filteredCves)');
  assert.doesNotMatch(json, /lifecycle|"entries"|"unresolved"|EXPLOITATION_CONFIRMED|correlations/);
  assert.equal(d.run('toCsv(filteredCves)').split('\n')[0], BASELINE.exports.csv.split('\n')[0]);
});

test('검색어 cwe: 는 번호가 같은 것만 — cwe:79 가 CWE-798 을 잡지 않는다', () => {
  const d = dashboard();
  d.run("allCves.find(c => c.id === 'CVE-2026-0005').cwe = ['CWE-798'];");
  assert.deepEqual(search(d, 'cwe:79'), [cve(3)]);
  assert.deepEqual(search(d, 'cwe:cwe-798'), [cve(5)]);
  assert.deepEqual(search(d, 'cwe:7'), []);
});

test('검색어 vendor: · product: 는 이름의 공백을 빼고 견준다 — 자동 완성 값으로 찾을 수 있다', () => {
  const d = dashboard();
  const values = d.run("buildAffectedFilter('vendor', 'vendor-filter'); JSON.stringify(suggestValues('vendor').map(v => v[0]))");
  assert.ok(JSON.parse(values).includes('apachesoftwarefoundation'), values);
  assert.deepEqual(search(d, 'vendor:apachesoftwarefoundation'), [cve(8)]);
  assert.deepEqual(search(d, 'product:windowsserver2019'), [cve(1)]);
  assert.deepEqual(search(d, 'product:nginx'), [cve(2)], '일부만 적어도 찾는다');
});

test('제품 · 벤더 목록에서 고른 이름은 같은 이름만 — 옆에 적힌 건수와 목록 건수가 같다', () => {
  const d = dashboard();
  const options = JSON.parse(d.run("buildAffectedFilter('product', 'product-filter'); JSON.stringify(topNames.product)"));
  const java = options.find(o => o.name === 'Java SE');
  assert.equal(java.count, 2);
  assert.deepEqual(ids(filterIds(d, "activeFilters.product = 'java se';")), [cve(6), cve(15)]);
  assert.deepEqual(ids(filterIds(d, "activeFilters.product = 'windows server 2019';")), [cve(1)],
                   "'Windows Server 2019 (Server Core installation)' 만 있는 CVE 는 다른 이름이다");
  assert.deepEqual(ids(filterIds(d, "activeFilters.product = 'windows';")), [], '일부만 아는 이름은 검색어 product: 로 찾는다');
  assert.deepEqual(ids(filterIds(d, "activeFilters.vendor = 'oracle';")), [cve(6), cve(15)]);
});

test('영향 제품 순위 — 이름을 onclick 코드에 넣지 않는다 (따옴표 · 역슬래시가 든 이름)', () => {
  const d = dashboard();
  d.run(`renderProductBars([{ product: "O'Reilly \\\\'); alert(1); ('", vendor: 'x', count: 3 }])`);
  const html = d.el('product-dist').innerHTML;
  assert.match(html, /onclick="filterByProduct\(this\.dataset\.product\)"/);
  assert.doesNotMatch(html, /filterByProduct\('/);
  d.run(`renderProductBars([{ product: 'a" onmouseover="alert(1)', vendor: '', count: 1 }])`);
  assert.match(d.el('product-dist').innerHTML, /data-product="a&quot; onmouseover=&quot;alert\(1\)"/, '큰따옴표는 속성 값 안에서 이스케이프된다');
});

test('CSV — 수식으로 읽힐 칸은 앞에 작은따옴표를 붙인다', () => {
  const d = dashboard();
  d.run("allCves[0].title = '=HYPERLINK(\"http://x.example\",\"click\")'; allCves[1].title = '-2+3'; allCves[2].title = '@SUM(A1)';");
  const csv = d.run('toCsv(allCves.slice(0, 4))').split('\n');
  assert.match(csv[1], /,"'=HYPERLINK\(""http:\/\/x\.example"",""click""\)",/);
  assert.match(csv[2], /,'-2\+3,/);
  assert.match(csv[3], /,'@SUM\(A1\),/);
  assert.doesNotMatch(csv[4], /,'/, '보통 글은 그대로');
});
