'use strict';
// 엔티티 계층(entities.js) · 뷰 모델(viewmodel.js) — CVE → 제품 → 사이클, CVE → 증거 → 출처 관계와 화면 값의 규칙.
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const LC = require('../docs/js/lifecycle.js');
const CTX = require('../docs/js/context.js');
const EN = require('../docs/js/entities.js');
const VM = require('../docs/js/viewmodel.js');
const { readJson } = require('./helpers/dashboard_vm');

const TODAY = '2026-09-27';
const CVES = readJson('dashboard_cves.json');
const PACKAGES = readJson('dashboard_packages.json').packages;
const LIFE = readJson('lifecycle_sample.json');
const ALIASES = require('../data/lifecycle_aliases.json');
const MATCHER = LC.createMatcher(LIFE, ALIASES);

function entityOf(cve, extra) {
  const affected = cve.affected || [];
  const match = MATCHER.matchCve(affected, PACKAGES[cve.id]);
  const lifecycle = LC.reduceMatch(match);
  return EN.buildEntities(cve, Object.assign({ affected, match, lifecycle, packages: PACKAGES[cve.id], products: LIFE.products,
                                               today: TODAY, files: { cves: '2026-09-27T03:00:00Z' } }, extra || {}));
}

test('엔티티 — 신호마다 근거가 이어지고, 있음이 아니면 근거가 없으며, 모름은 사유가 있다', () => {
  for (const cve of CVES) {
    const e = entityOf(cve);
    const ids = new Set([...e.evidence.map(x => x.id), ...e.remediation.map(x => x.id), ...e.scores.map(x => x.id),
                         ...e.products.flatMap(p => (p.lifecycle.cycles || []).map(c => c.id))]);
    for (const s of Object.values(e.signals)) {
      if (s.state === 'yes') {
        assert.ok(s.supportedBy.length > 0, `${cve.id} ${s.code}: 있음이면 근거가 있다`);
        for (const id of s.supportedBy) assert.ok(ids.has(id), `${cve.id} ${s.code}: 근거 ${id} 가 엔티티에 있다`);
      } else {
        assert.deepEqual(s.supportedBy, [], `${cve.id} ${s.code}: 있음이 아니면 근거를 달지 않는다`);
      }
      if (s.state === 'unknown' && s.code !== 'EXPLOITATION_CONFIRMED') {
        assert.ok(s.reasons.length > 0, `${cve.id} ${s.code}: 모름은 사유가 있다 (모름 ≠ 없음)`);
      }
    }
    for (const c of e.correlations) {
      for (const p of c.parts) assert.equal(e.signals[p.code].state, p.negated ? 'no' : 'yes', `${cve.id} ${c.code}`);
    }
  }
});

test('엔티티 — 증거는 출처 엔티티 · 증거 유형 · 연결 방법을 가진다 (출처와 유형을 섞지 않는다)', () => {
  const types = new Set(Object.keys(EN.EVIDENCE_TYPES));
  for (const cve of CVES) {
    for (const ev of entityOf(cve).evidence) {
      assert.ok(EN.SOURCES[ev.source], `${cve.id} ${ev.id}: 출처 ${ev.source}`);
      assert.ok(types.has(ev.type), `${cve.id} ${ev.id}: 유형 ${ev.type}`);
      // 참고(info) 행은 다른 유형의 판정을 곁들여 보여 주는 것 — 예: 공개 exploit 칸의 SSVC Exploitation=poc
      assert.ok(EN.SOURCES[ev.source].provides.includes(ev.type) || ev.status === 'info',
                `${cve.id} ${ev.id}: ${ev.source} 가 ${ev.type} 를 준다`);
      assert.ok(['present', 'absent', 'unknown', 'info'].includes(ev.status));
      assert.ok(ev.basis, `${cve.id} ${ev.id}: 연결 방법`);
      assert.ok(ev.observed && 'at' in ev.observed, `${cve.id} ${ev.id}: Argus 확인 시각 칸`);
    }
  }
});

test('엔티티 — 원 출처 날짜는 cve-evidence.json 에서만, 제목 · 설명의 출처는 cve-facts.json 기록대로', () => {
  const cve = Object.assign({}, CVES[0], { analysis: { root_cause: 'AI-TEXT-MARKER' } });
  const plain = entityOf(cve);
  assert.ok(plain.evidence.every(ev => ev.published === null), '파일이 없으면 공개일을 만들지 않는다');
  assert.equal(plain.texts.find(t => t.id === 'text:title').origin, 'generated', '한국어 제목 — 파일 전에는 원문이 아니라는 것만 안다');
  assert.equal(plain.texts.find(t => t.id === 'text:description').origin, 'source', '영문 설명 — 파일 전에는 글자로만 판단');
  const evidence = { schema: 1, actions: ['Apply updates.'], kev: { [cve.id]: ['2026-09-01', '2026-10-10', 0, [], 'X'] }, edb: {},
                     msf: { [cve.id]: [['exploit/x', 500, '2026-08-30', 'exploit', 0]] } };
  const facts = { schema: 1, facts: { [cve.id]: { o: ['ai', 'source'], t: 'Orig', d: 'Orig desc', a: 'cna-x', p: [[cve.affected[0].vendor, cve.affected[0].product, 'CISA KEV']] } } };
  const e = entityOf(cve, { evidence: EN.evidenceFor(evidence, cve.id), facts: EN.factsFor(facts, cve.id), files: { evidence: '2026-09-27T04:00:00Z' } });
  const kev = e.evidence.find(ev => ev.source === 'cisa-kev' && ev.type === 'exploitation');
  assert.deepEqual(kev.published, { date: '2026-09-01', label: 'KEV 등재일' });
  assert.equal(kev.extra.action, 'Apply updates.');
  const msf = e.evidence.find(ev => ev.source === 'metasploit');
  assert.equal(msf.published, null, 'Metasploit DisclosureDate 는 취약점 공개일이라 모듈 공개일 칸에 넣지 않는다');
  assert.equal(msf.extra.modules[0].rank_name, 'great');
  assert.equal(e.texts.find(t => t.id === 'text:title').origin, 'ai');
  assert.equal(e.texts.find(t => t.id === 'text:description').origin, 'source');
  assert.equal(e.texts.find(t => t.id === 'text:title:original').value, 'Orig');
  assert.equal(e.cve.assigner, 'cna-x');
  assert.equal(e.products[0].source, 'CISA KEV', '제품 항목을 채운 출처');
  const dump = JSON.stringify(Object.assign({}, e, { analysis: null, derived: null }));
  assert.doesNotMatch(dump, /AI-TEXT-MARKER/, 'AI 분석 글은 사실 · 파생 엔티티에 들어가지 않는다');
  assert.equal(e.analysis.root_cause, 'AI-TEXT-MARKER');
});

test('영향 버전 → 범위 · 영향 없음 시작 버전 (수정 버전이라고 단정하지 않는다)', () => {
  const r = EN.rangesOf('18.7 부터 18.11.12 이전, 19.0 부터 19.0.9 이전, 20.1 이하');
  assert.equal(r.parsed, true);
  assert.deepEqual(r.ranges.map(x => [x.lower, x.upper, x.kind]), [['18.7', '18.11.12', '이전'], ['19.0', '19.0.9', '이전'], [null, '20.1', '이하']]);
  assert.deepEqual(r.unaffectedFrom, ['18.11.12', '19.0.9'], "'이하' 의 상한은 영향 버전이라 넣지 않는다");
  assert.deepEqual(EN.rangesOf('정보 없음'), { ranges: [], unaffectedFrom: [], parsed: false });
  // 실측(CVE-2021-44228): 상한이 버전이 아닌 레코드 — 범위로 읽지 않고 '영향 없음 시작 버전'도 만들지 않는다
  const odd = EN.rangesOf('2.0-beta9 부터 log4j-core* 이전');
  assert.equal(odd.ranges[0].valid, false);
  assert.deepEqual(odd.unaffectedFrom, []);
  assert.equal(EN.rangesOf('1.2.3 (단일 버전)').ranges[0].valid, true);
  const git = EN.rangesOf('1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 부터 5e6b9b3a1f0e2d4c6b8a0e2d4c6b8a0e2d4c6b8a 이전');
  assert.equal(git.ranges[0].valid, false, '커널 git 커밋 해시는 버전이 아니다(숫자로 시작해도)');
  assert.deepEqual(git.unaffectedFrom, []);
  const open = EN.rangesOf('unspecified 부터 12.2 이전');
  assert.equal(open.ranges[0].valid, false, '하한을 모르면 범위 표기는 원문 그대로');
  assert.deepEqual(open.unaffectedFrom, ['12.2'], '상한이 버전이면 영향 없음 시작 버전은 쓴다');
});

test('뷰 모델 — KPI · 행렬 · 상관은 집계와 같은 값, 목록 행은 모름을 모름으로', () => {
  const items = CVES.map(cve => {
    const match = MATCHER.matchCve(cve.affected || [], PACKAGES[cve.id]);
    const lc = LC.reduceMatch(match);
    const s = CTX.signals(cve, { packages: PACKAGES[cve.id], lifecycle: lc, products: LIFE.products, today: TODAY,
                                 affectedCount: (cve.affected || []).length });
    return CTX.aggregateItem(cve, { states: s.states, correlations: CTX.correlationsOf(s.states) }, lc);
  });
  const agg = CTX.aggregate(items, { days: CTX.trendDays('2026-09-27T03:00:00+00:00', 30) });
  const k = Object.fromEntries(VM.kpis(agg, { cve: { total: 16, recent_24h: 5 } }).map(x => [x.id, x]));
  assert.equal(k['stat-kev'].value, CVES.filter(c => c.is_kev).length);
  assert.equal(k['stat-weapon'].value, CVES.filter(c => c.has_metasploit_module || c.has_public_exploit).length);
  assert.equal(k['stat-poc'].value, CVES.filter(c => c.has_poc).length);
  assert.equal(k['stat-ai'].value, CVES.filter(c => c.ai_discovered).length);
  const mx = VM.matrix(agg);
  for (const [key, cell] of Object.entries(mx.cells)) {
    const [i, j] = key.split('|').map(Number);
    const n = items.filter(it => it.states[mx.axes[i].code] === 'yes' && it.states[mx.axes[j].code] === 'yes').length;
    assert.equal(cell.n, n, `${mx.axes[i].code} × ${mx.axes[j].code}`);
  }
  const corr = VM.correlations(agg);
  assert.equal(corr.length, CTX.CORRELATIONS.length);
  assert.deepEqual(corr.map(c => c.n), corr.map(c => c.n).slice().sort((a, b) => b - a));
  const ov = VM.overview(agg);
  assert.equal(ov.days.length, 30);
  assert.equal(ov.sum, CVES.filter(c => c.published >= '2026-08-29' && c.published <= '2026-09-27').length);
  const row = VM.listRow(CVES.find(c => c.id === 'CVE-2026-0005'), {});
  assert.equal(row.cvss, null, 'CVSS 0 → 점수 없음');
  const row16 = VM.listRow(CVES.find(c => c.id === 'CVE-2026-0016'), {});
  assert.equal(row16.epss, null, 'EPSS 0 → 미채점');
  const rec = VM.recent([{ id: 'X', published: '2026-09-26', signals: ['CISA_KEV', 'EXPLOITATION_CONFIRMED'], correlations: [] }], '2026-09-27T03:00:00Z');
  assert.equal(rec[0].ago, '어제 공개');
  assert.deepEqual(rec[0].signalLabels, ['CISA KEV'], 'CISA KEV 가 있으면 악용 근거를 겹쳐 적지 않는다');
});

test('뷰 모델 — 출처 표는 외부 출처만 묶음별로 한 번씩, 주는 정보 · 건수 · 갱신 · 이용 조건과 함께', () => {
  const groups = VM.sources(EN, null, {});
  const ids = groups.flatMap(g => g.rows.map(r => r.id));
  const external = EN.SOURCE_ORDER.filter(id => EN.SOURCES[id].kind === 'source');
  assert.deepEqual(ids.slice().sort(), external.slice().sort(), '외부 출처는 빠짐없이, 내부 엔티티(Argus · 룰 색인 · AI 번역)는 싣지 않는다');
  assert.equal(new Set(ids).size, ids.length, '출처마다 한 번');
  for (const r of groups.flatMap(g => g.rows)) {
    assert.ok(r.role && r.cadence, `${r.id}: 주는 정보 · 갱신 주기`);
    assert.ok(r.terms.length > 0 && r.terms.every(t => t.label), `${r.id}: 이용 조건`);
    for (const t of r.terms) if (t.url) assert.match(t.url, /^https:\/\//, `${r.id}: ${t.label}`);
    assert.equal(r.count, null, `${r.id}: 집계 전에는 모름(null)이지 0이 아니다`);
  }
  assert.ok(!EN.SOURCES.gemini && !EN.SOURCES.nvd, 'AI 분석 도구 행과 CVE 레코드에 합친 NVD 행은 없다');
  const agg = { total: 16, sources: { cisa_kev: 2, epss_scored: 15 }, signals: { PATCH_AVAILABLE: { yes: 3, no: 1, unknown: 12 } } };
  const rowOf = id => VM.sources(EN, agg, { sigma: 1 }).flatMap(g => g.rows).find(r => r.id === id);
  assert.equal(rowOf('cve-record').count, 16);
  assert.equal(rowOf('cisa-kev').count, 2);
  assert.equal(rowOf('osv').count, 4, 'OSV 는 기록이 있는 CVE(수정 버전 있음 + 없음)');
  assert.equal(rowOf('sigma').count, 1, '룰 저장소별 건수는 화면이 센 값');
  assert.equal(rowOf('cwe').count, null, 'CWE 건수는 화면이 전체 목록에서 센 값만 — 집계에는 없다');
  assert.equal(VM.sources(EN, agg, { cwe: 9 }).flatMap(g => g.rows).find(r => r.id === 'cwe').count, 9);
  assert.equal(rowOf('metasploit').count, null, '집계에 없는 값은 모름');
  assert.deepEqual(rowOf('et-open').terms.map(t => t.label), ['BSD']);
  assert.deepEqual(rowOf('snort-community').terms.map(t => t.label), ['GPLv2']);
  // 이용 조건 설명 — 이름과 링크만으로 알 수 없는 조건만 명사로 짧게 (표준 라이선스는 이름 · 링크로 충분)
  const notes = VM.sources(EN, null, {}).flatMap(g => g.rows).flatMap(r => r.terms.filter(t => t.note).map(t => [r.id, t.note]));
  assert.deepEqual(notes, [['cve-record', '저작권 표기 · 약관 문구 필요'], ['cve-record', 'NVD 고지 문구 필요'],
                           ['cwe', '저작권 표기 · 약관 문구 필요'],
                           ['osv', 'GitHub Advisory Database CC-BY 4.0 · Ubuntu CC-BY-SA 4.0 등'],
                           ['vulncheck-kev', '출처 표기 필수'], ['first-epss', '출처 표기 요청']]);
  assert.equal(rowOf('vulncheck-kev').terms[0].label, 'VulnCheck 이용 조건');
  // 예약 주기 = yml 예약 · 캐시 수명 (argus-fast */5 · KEV 캐시 1시간 · PoC 색인 매시 · 6시간 · 24시간 · 주간 정비 · 매일 수명주기)
  const cadence = Object.fromEntries(VM.sources(EN, null, {}).flatMap(g => g.rows).map(r => [r.id, r.cadence]));
  assert.deepEqual(cadence, {
    'cve-record': '5분마다 (변경분)', cwe: '수동 (새 판이 나올 때)', osv: '매주', 'ai-discovery': '6시간마다',
    'cisa-kev': '매시', 'vulncheck-kev': '6시간마다', 'cisa-adp': '5분마다 (CVE 레코드와 함께)', 'first-epss': '6시간마다',
    'exploit-db': '매일', metasploit: '매일', 'poc-in-github': '매시',
    sigma: '매주', 'et-open': '매주', 'snort-community': '매주', splunk: '매주', yara: '매주', nuclei: '매일',
    endoflife: '매일',
  });
});
