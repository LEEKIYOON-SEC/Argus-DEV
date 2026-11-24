'use strict';
// 화면 뼈대 — cve.html 구조 · 스크립트 순서 · 테마 토큰 · 라이선스 표 위치(INVARIANTS §9-1) · 모듈이 빠졌을 때의 동작.
process.env.TZ = 'UTC';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadDashboard, withFixture, filterIds } = require('./helpers/dashboard_vm');
const { rowIds } = require('./helpers/dashboard_scenarios');

const ROOT = path.resolve(__dirname, '..');
const HTML = fs.readFileSync(path.join(ROOT, 'docs', 'cve.html'), 'utf8');
const CSS = fs.readFileSync(path.join(ROOT, 'docs', 'css', 'style.css'), 'utf8');

test('cve.html — 화면마다 view-* 와 사이드바 항목이 있고, 스크립트는 의존 순서대로', () => {
  for (const v of ['dashboard', 'cves', 'detail', 'lifecycle', 'sources']) {
    assert.match(HTML, new RegExp(`id="view-${v}"`), `view-${v}`);
  }
  for (const v of ['dashboard', 'cves', 'lifecycle', 'sources']) {
    assert.match(HTML, new RegExp(`class="view-tab[^"]*"[^>]*data-view="${v}"`), `사이드바 ${v}`);
  }
  // 최근 본 CVE 는 사이드바가 아니라 검색창에서(빈 검색창을 누르면)
  assert.doesNotMatch(HTML, /data-view="detail"|id="side-detail/, '사이드바의 최근 본 CVE 한 건 칸은 없앴다');
  const scripts = [...HTML.matchAll(/<script src="js\/([^"]+)"><\/script>/g)].map(m => m[1]);
  assert.deepEqual(scripts, ['lifecycle.js', 'context.js', 'entities.js', 'cwe-data.js', 'cwe.js', 'viewmodel.js', 'cve-dashboard.js',
                             'cve-detail.js', 'dashboard-view.js', 'lifecycle-view.js', 'sources-view.js']);
  for (const s of scripts) assert.ok(fs.existsSync(path.join(ROOT, 'docs', 'js', s)), s);
  assert.doesNotMatch(HTML, /chart\.js/, '예전 추이 차트 스크립트는 없앴다');
  // 기존 id — 회귀 도구 · 외부 링크가 쓰는 것
  for (const id of ['search-input', 'cve-table-body', 'page-info', 'prev-btn', 'next-btn', 'active-chips', 'filter-count', 'severity-dist',
                    'product-dist', 'modal-id', 'modal-title', 'modal-body', 'modal-scores', 'modal-signals', 'modal-sev-badge',
                    'stat-total', 'stat-kev', 'stat-weapon', 'stat-poc', 'stat-ai', 'stat-24h-sub', 'updated-time',
                    'search-recent', 'modal-type']) {
    assert.match(HTML, new RegExp(`id="${id}"`), id);
  }
  const ths = HTML.slice(HTML.indexOf('<table class="cve-table">'), HTML.indexOf('</thead>', HTML.indexOf('<table class="cve-table">')));
  assert.equal((ths.match(/<th[ >]/g) || []).length, 5, '목록 5칸 — CVE·알림 · 요약·영향 제품 · CVSS·EPSS · 위협 신호(지원 상태 포함) · 탐지·수정');
  assert.doesNotMatch(ths, /h-lc/, '지원 상태 칸은 없앴다 — 값이 있을 때만 위협 신호 칸의 칩으로');
  // 조건 줄 세 줄 — 심각도 / 조건 칩 / 점수 · 필터. 나란히 보기도 같다(조건을 필터 안으로 옮기지 않는다)
  const bar = HTML.slice(HTML.indexOf('<section class="filter-bar">'), HTML.indexOf('<div class="active-chips"'));
  assert.deepEqual([...bar.matchAll(/<div class="filter-row ([^"]+)">/g)].map(m => m[1]), ['primary', 'chip-row', 'score-row']);
  const at = id => bar.indexOf(`id="${id}"`);
  assert.ok(at('severity-seg') < at('quick-chips') && at('quick-chips') < at('cvss-min') && at('cvss-min') < at('epss-min')
            && at('epss-min') < at('filter-toggle'), '심각도 → 조건 칩 → CVSS · EPSS · 필터');
  assert.doesNotMatch(HTML, /filter-split/);
  // 대시보드 — 주요 지표 → 최근 동향 → 신호 조합(2/3) · 30일 공개(1/3)
  const dash = HTML.slice(HTML.indexOf('id="view-dashboard"'), HTML.indexOf('id="view-cves"'));
  assert.ok(dash.indexOf('id="dash-kpis"') < dash.indexOf('id="dash-today"') && dash.indexOf('id="dash-today"') < dash.indexOf('class="dash-main"'),
            '주요 지표가 맨 위, 최근 동향이 가운데');
  // 제목 옆 유형은 제목과 따로 — modal-title 에는 제목 글자만(회귀 도구 · aria-labelledby 가 쓴다)
  assert.match(HTML, /<h2 class="m-title"><span id="modal-title">-<\/span><span class="h-type" id="modal-type" hidden><\/span><\/h2>/);
  // 화면마다 설명 카드는 '설명' 버튼으로 연다 — 버튼이 가리키는 카드가 있어야 한다
  const helps = [...HTML.matchAll(/class="help-btn"[^>]*aria-controls="([^"]+)"[^>]*>([^<]+)</g)];
  assert.deepEqual(helps.map(m => m[2]), ['설명', '설명', '설명', '설명']);
  for (const [, id] of helps) assert.match(HTML, new RegExp(`class="help-card" id="${id}" hidden`), id);
  // 접어 둔 대시보드 칸 — 버튼마다 여는 패널이 있다
  for (const [, id] of HTML.matchAll(/class="fold-btn"[^>]*aria-controls="([^"]+)"/g)) assert.match(HTML, new RegExp(`id="${id}" hidden`), id);
});

test('하단은 늘 보이는 고지만, 출처별 이용 조건은 데이터 출처 화면 한 곳에 (INVARIANTS §9-1)', () => {
  const footer = HTML.slice(HTML.indexOf('<footer'), HTML.indexOf('</footer>'));
  assert.ok(footer.length > 0);
  assert.doesNotMatch(footer, /<details|<table/, '고지는 접지 않고, 조건 표는 하단에 두지 않는다');
  for (const notice of ['This product uses the NVD API but is not endorsed or certified by the NVD.',
                        'This product uses <a href="https://vulncheck.com/kev"', '>VulnCheck KEV</a>.',
                        'Copyright © 1999-2026, The MITRE Corporation.', '취약점 유형(CWE): Copyright © 2006–2026, The MITRE Corporation.',
                        'Copyright 2020 endoflife.date contributors', 'FIRST.org']) {
    assert.ok(footer.includes(notice), notice);
  }
  assert.match(footer, /href="\?view=sources" onclick="openSources\(event\)"/, '조건은 데이터 출처 화면으로 보낸다');
  assert.doesNotMatch(footer, /Gemini|Gemma|Google AI Studio|무료 티어|Turso|Slack/, 'AI 도구 · 요금제 · 운영 구성은 싣지 않는다');
  const sources = HTML.slice(HTML.indexOf('id="view-sources"'), HTML.indexOf('</main>'));
  // 약관 원문 — cve.org 이용약관 문구 그대로(CVE™). 사본에 저작권 표기와 이 문구를 함께 실어야 한다.
  assert.ok(sources.includes("distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy."));
  assert.match(sources, /Copyright © 1999-2026, The MITRE Corporation\./);
  // CWE 이용약관 — 사본마다 MITRE 저작권 표기와 약관 문구를 함께. 화면의 문구는 docs/js/cwe-data.js 머리(src/update_cwe.py)와 같다.
  const cwe = sources.slice(sources.indexOf('id="terms-cwe"'), sources.indexOf('</div>', sources.indexOf('id="terms-cwe"')));
  assert.match(cwe, /Copyright © 2006–2026, The MITRE Corporation\. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation\./);
  const tou = (cwe.match(/<blockquote lang="en">([^<]+)<\/blockquote>/) || [])[1];
  assert.ok(tou && tou.includes('on the condition that you reproduce MITRE’s copyright designation and this license in any such copy'));
  const dataHead = fs.readFileSync(path.join(ROOT, 'docs', 'js', 'cwe-data.js'), 'utf8').split('(function (root)')[0];
  assert.ok(dataHead.includes(tou), '화면의 CWE 약관 문구 = 데이터 파일에 실은 문구');
  assert.match(cwe, /href="https:\/\/cwe\.mitre\.org\/about\/termsofuse\.html"/);
  assert.match(sources, /Copyright \(c\) 2003-2026, Emerging Threats/, 'ET Open BSD 라이선스 전문');
  assert.match(sources, /rules\.emergingthreats\.net ↗<\/a> · SID 2000000–2799999 룰에 적용<\/p>/);
  assert.ok(!sources.includes('사본에 함께 실어야') && !sources.includes('Argus가 싣는'), '약관 원문 칸의 설명 문장은 뺐다');
  // 예약 주기는 GitHub Actions 예약 기준 — 실제로는 늦어지거나 건너뛸 수 있다는 안내와 실제 반영 시각을 함께 둔다
  const foot = (sources.match(/<p class="src-foot">([\s\S]*?)<\/p>/) || [])[1] || '';
  assert.match(foot, /GitHub Actions/);
  assert.match(foot, /늦게 시작하거나 건너뛸 수 있어/);
  assert.match(foot, /'기준' 시각/);
  assert.match(sources, /매시 18분에 예약된 작업이 내보낼 때 바뀝니다/, '화면 데이터가 바뀌는 때');
  for (const gone of ['id="dash-coverage"', 'id="src-conflicts"', 'id="dash-quality"', 'source-license', 'openLicense', 'src-table']) {
    assert.ok(!HTML.includes(gone), `없앤 칸: ${gone}`);
  }
});

test('제품 수명주기 화면 — 검색 · 90일 버튼 · 분류 칸만, 예전 필터(상태 숫자 · 정렬 · CVE 연결)는 없다', () => {
  const lc = HTML.slice(HTML.indexOf('id="view-lifecycle"'), HTML.indexOf('id="view-sources"'));
  for (const id of ['lc-asof', 'lc-meta', 'lc-search', 'lc-soon', 'lc-soon-n', 'lc-count', 'lc-cats']) {
    assert.match(lc, new RegExp(`id="${id}"`), id);
  }
  for (const gone of ['lc-kpis', 'lc-sort', 'lc-linked', 'lc-vendor', 'id="lc-product"', 'lc-status-seg', 'lc-window', 'lc-products',
                      'lc-unavailable', 'CVE가 연결된 것만', '연결된 CVE 많은 순']) {
    assert.ok(!lc.includes(gone), `없앤 것: ${gone}`);
  }
  assert.match(lc, /id="lc-soon" aria-pressed="false"/);
  assert.match(lc, /CVE와 연결한 지원 상태는 CVE 상세에서 보여 줍니다/);
  assert.match(lc, /오늘이 EOL인 버전은 이미 EOL로 봅니다/, '90일 기준을 설명에 적는다');
  for (const sel of ['.lc-cat-head', '.lc-grid', '.lc-pick', '.lc-detail', 'table.lc-rel', '.lc-dday', '.lc-soon-btn', '.lc-msum']) {
    assert.ok(CSS.includes(sel), `새 스타일 ${sel}`);
  }
  for (const gone of ['.lc-kpi', '.lc-soon-tile', 'lc-catalog', '.obs-kev', '.kpi-grid', '.lc-search-wrap', '.lc-prod-obs']) {
    assert.ok(!CSS.includes(gone), `옛 스타일 ${gone}`);
  }
});

// 화면 스크립트(classic script)는 전역 하나를 함께 쓴다 — 뒤에 읽는 파일의 같은 이름이 앞의 것을 조용히 덮는다
// (예: 검색창의 최근 본 CVE 와 대시보드의 최근 CVE 칸이 같은 함수 이름을 쓰면 한쪽이 동작하지 않는다).
test('화면 스크립트 — 같은 이름의 전역 함수 · 변수를 두 번 선언하지 않는다', () => {
  const seen = new Map();
  for (const f of ['cve-dashboard.js', 'cve-detail.js', 'dashboard-view.js', 'lifecycle-view.js', 'sources-view.js']) {
    const src = fs.readFileSync(path.join(ROOT, 'docs', 'js', f), 'utf8');
    for (const m of src.matchAll(/^(?:async\s+)?function\s+([\w$]+)|^(?:const|let|var)\s+([\w$]+)/gm)) {
      const name = m[1] || m[2];
      assert.ok(!seen.has(name), `${name}: ${seen.get(name)} · ${f}`);
      seen.set(name, f);
    }
  }
  assert.ok(seen.size > 300);
});

test('목록 · 상세 스타일 — 새 칸(유형 칩 · 등급 구분 줄 · 최근 본 CVE · 등급 근거)이 있고, 없앤 칸의 스타일은 없다', () => {
  for (const sel of ['.c-type', '.c-snip', '.cve-id.is-seen', 'tr.grp-row', '.grp-dot', '.search-recent', '.sr-item', '.tier-menu', '.tier-pop',
                     '.fact.is-type', '.h-type', '#d-product { container-type: inline-size; }']) {
    assert.ok(CSS.includes(sel), `새 스타일 ${sel}`);
  }
  for (const gone of ['.h-lc', '.c-lc', '.side-sub', '.side-id', '.t-due', '.t-link.is-hot', '.q-more', 'is-extra', '.q-chip b']) {
    assert.ok(!CSS.includes(gone), `옛 스타일 ${gone}`);
  }
  // 상세 위협 신호 — 신호마다 그 줄 아래 출처 표 칸 · 칩 줄, 탐지 룰은 룰마다 한 줄(§6 '화면 개편 5차'). '출처별로 보기' · 룰 상자는 없앴다.
  for (const sel of ['.ev-panel[hidden]', '.st-line', '.st-panels .ev-panel', '[data-panel][aria-expanded="true"]::after', '.is-jump::after',
                     '.rule-item', '.rule-row', '.rule-act', '.rule-body-btn', '.rule-preview[hidden]']) {
    assert.ok(CSS.includes(sel), `새 스타일 ${sel}`);
  }
  for (const gone of ['details.d-more', '.d-more-body', '.d-more-go', '.rules-details', '.rules-section', '.rule-block', '.rule-header', '.trust-badge']) {
    assert.ok(!CSS.includes(gone), `옛 스타일 ${gone}`);
  }
  // 한 줄짜리 Snort · Suricata 룰도 끝까지 보이게 줄을 바꾼다(예전 white-space: pre 는 칸 폭의 약 16%만 보였다)
  assert.match(CSS, /\.rule-preview \{[^}]*white-space: pre-wrap; overflow-wrap: anywhere;/);
  // 대시보드 — 3칸 격자에 신호 조합 2칸, 주요 지표 칸 사이 16px(지표 2칸 · 4칸 경계가 1/3 · 2/3 선과 맞음), 30일 표는 높이 고정 + 스크롤
  assert.match(CSS, /\.dash-main \{ display: grid; grid-template-columns: repeat\(3, minmax\(0, 1fr\)\); gap: 16px;/);
  assert.match(CSS, /\.dash-main > \.corr-panel \{ grid-column: span 2; \}/);
  assert.match(CSS, /\.kpi-strip \{ display: grid; grid-template-columns: repeat\(6, minmax\(0, 1fr\)\); gap: 16px;/);
  assert.match(CSS, /\.ov-table \.table-scroll \{ max-height: 400px;/);
  // ID 칸 — 심각도 배지와 공개일(YYYY-MM-DD)이 한 줄에 들어가는 폭. 나란히 보기도 넓은 목록과 같게
  assert.match(CSS, /\n\.cve-table \.h-id \{ width: 176px; \}/);
  assert.match(CSS, /\.content\.is-split \.cve-table \.h-id \{ width: 176px; \}/);
  // '공개' 글자는 표에서는 숨기고(머리글이 알려 준다) 머리글이 없는 카드(1000px 이하)에서만 보인다
  assert.match(CSS, /\n\.c-date-k \{ display: none; \}/);
  assert.match(block(CSS, '@media (max-width: 1000px)'), /\.c-date-k \{ display: inline; \}/);
  // ID 칸 둘째 줄은 넘치면 다음 줄로('AI 발견' 태그가 칸 밖으로 잘리지 않게)
  assert.match(CSS, /\.c-meta \{ display: flex; flex-wrap: wrap;/);
});

function block(css, start) {
  const i = css.indexOf(start);
  assert.ok(i >= 0, start);
  let depth = 0;
  for (let j = css.indexOf('{', i); j < css.length; j++) {
    if (css[j] === '{') depth++;
    else if (css[j] === '}' && --depth === 0) return css.slice(css.indexOf('{', i) + 1, j);
  }
  throw new Error(`닫히지 않은 블록 ${start}`);
}
const decls = body => body.replace(/\/\*[\s\S]*?\*\//g, '').split(';').map(x => x.trim().replace(/\s+/g, ' ')).filter(Boolean).sort();

test('테마 — 라이트 토큰 두 블록(OS 설정 · 테마 버튼)이 같고, 다크 기본값과 같은 이름을 덮는다', () => {
  const media = block(CSS, '@media (prefers-color-scheme: light) {\n  :root:not([data-theme="dark"])');
  const inner = block(media, ':root:not([data-theme="dark"])');
  const attr = block(CSS, ':root[data-theme="light"] {');
  assert.deepEqual(decls(inner), decls(attr));
  const root = decls(block(CSS, ':root {')).map(d => d.split(':')[0]);
  for (const d of decls(attr)) assert.ok(root.includes(d.split(':')[0]), `다크 기본값에도 있음: ${d}`);
  assert.match(block(CSS, ':root {'), /color-scheme: dark/);
  assert.match(attr, /color-scheme: light/);
});

test('뷰 모델 스크립트가 없어도 목록 · 검색 · 상세 머리글은 동작한다', () => {
  const d = withFixture(loadDashboard([{ file: 'docs/js/cve-dashboard.js' }, { file: 'docs/js/cve-detail.js' }, { file: 'docs/js/dashboard-view.js' }]));
  d.run('dataReady = true;');
  const ids = filterIds(d, "activeFilters.search = 'has:kev';");
  assert.deepEqual([...ids].sort(), ['CVE-2026-0001', 'CVE-2026-0004', 'CVE-2026-0010']);
  const html = d.el('cve-table-body').innerHTML;
  assert.deepEqual(rowIds(html), ids);
  assert.match(html, /class="c-none"[^>]*>미확인</, '판단 모듈이 없으면 없음이 아니라 미확인');
  d.run("showDetail('CVE-2026-0001')");
  assert.equal(d.el('modal-id').textContent, 'CVE-2026-0001');
  assert.match(d.el('modal-body').innerHTML, /id="d-product"[\s\S]*id="d-tech"/);
});
