'use strict';
// 수명주기 기능 이전 대시보드(docs/js/cve-dashboard.js)의 동작을 고정하는 시나리오.
// tests/tools/make_dashboard_baseline.js 가 이 목록을 옛 코드로 돌려 기준값을 만들고,
// tests/dashboard.test.js 가 같은 목록을 지금 코드로 돌려 비교한다.
const { filterIds, RESET } = require('./dashboard_vm');

const SEARCHES = [
  '', 'cvss:>=9', 'cvss:<5', 'cvss:=9.8', 'epss:>=10', 'epss:<1', 'tier:t0', 'tier:t2',
  'vendor:microsoft', 'vendor:f5', 'product:nginx', 'product:windows server', 'cwe:79', 'cwe:cwe-787',
  'has:kev', 'has:msf', 'has:nuclei', 'has:edb', 'has:poc', 'has:rules', 'has:ai', 'has:auto',
  'has:ransom', 'has:patched', 'has:foo', 'windows', 'CVE-2026-0003', 'nginx 1.25', 'unknownword',
  'cvss:>=9 has:kev vendor:microsoft', 'has:kev has:rules', 'epss:>=10 tier:t1', 'CVSS:>=7 Vendor:Oracle',
];

const FILTERS = {
  cvssMin7: 'activeFilters.cvssMin = 7;',
  epssMin10: 'activeFilters.epssMin = 10;',
  vendorMicrosoft: "activeFilters.vendor = 'microsoft';",
  productPhp: "activeFilters.product = 'php';",
  severityCritical: "activeFilters.severity = new Set(['Critical']);",
  severityNoLow: "activeFilters.severity = new Set(['Critical', 'High', 'Medium', 'None']);",
  signalKev: "activeFilters.signals.add('kev');",
  signalWeaponPoc: "activeFilters.signals.add('weaponized'); activeFilters.signals.add('poc');",
  signalRules: "activeFilters.signals.add('rules');",
  signalAuto: "activeFilters.signals.add('auto');",
  signalAi: "activeFilters.signals.add('ai');",
  signalPatched: "activeFilters.signals.add('patched');",
  kernelHide: "activeFilters.kernel = 'hide';",
  kernelOnly: "activeFilters.kernel = 'only';",
  month08: "activeFilters.month = '2026-08';",
  day0921: "activeFilters.day = '2026-09-21';",
  combo: "activeFilters.cvssMin = 7; activeFilters.signals.add('kev'); activeFilters.search = 'windows';",
};

const SORTS = [
  ['cvss'], ['cvss', 'cvss'], ['epss'], ['id'], ['id', 'id'], ['date'],
];

function rowIds(html) {
  // 기준 파일(변경 전 HTML)은 onclick="showDetail('ID')", 지금은 ID 를 data-id 에만 두고 onclick 이 그것을 읽는다.
  const old = [...String(html).matchAll(/showDetail\('([^']+)'\)/g)].map(m => m[1]);
  return old.length ? old : [...String(html).matchAll(/<tr [^>]*data-id="([^"]+)"[^>]*onclick="showDetail\(this\.dataset\.id\)"/g)].map(m => m[1]);
}

function capture(dash, code) {
  dash.run(`__captured = null; downloadBlob = (content, filename, mime) => { __captured = { content, filename, mime }; };`);
  dash.run(code);
  const c = dash.run('__captured');
  return c ? { content: c.content, filename: String(c.filename).replace(/\d{4}-\d{2}-\d{2}/, 'DATE'), mime: c.mime } : null;
}

function collect(dash) {
  const out = { searches: {}, filters: {}, sorts: {}, parse: {}, exports: {}, stats: {}, detail: {}, ui: {} };

  for (const q of SEARCHES) out.searches[q] = filterIds(dash, `activeFilters.search = ${JSON.stringify(q)};`);
  for (const [name, code] of Object.entries(FILTERS)) out.filters[name] = filterIds(dash, code);
  for (const seq of SORTS) {
    dash.run(RESET);
    for (const f of seq) dash.run(`sortBy(${JSON.stringify(f)})`);
    out.sorts[seq.join('>')] = dash.run('filteredCves.map(c => c.id)');
  }
  for (const q of ['cvss:>=9 has:kev', 'foo bar', 'vendor:apache product:http', 'epss:<=1.5 x']) {
    out.parse[q] = JSON.parse(JSON.stringify(dash.run(`parseQuery(${JSON.stringify(q)})`)));
  }

  filterIds(dash, '');
  out.ui.rows = dash.el('cve-table-body').innerHTML;
  out.ui.pageInfo = dash.el('page-info').textContent;
  filterIds(dash, "activeFilters.search = 'nomatchatall';");
  out.ui.emptyRows = dash.el('cve-table-body').innerHTML;
  filterIds(dash, "activeFilters.cvssMin = 7; activeFilters.signals.add('kev'); activeFilters.search = 'windows'; activeFilters.vendor = 'microsoft';");
  out.ui.chips = dash.el('active-chips').innerHTML;
  out.ui.filterCount = dash.el('filter-count').textContent;
  dash.run("clearFilter('signal', 'kev')");
  out.ui.afterClearSignal = dash.run('filteredCves.map(c => c.id)');
  dash.run("clearFilter('search', '')");
  out.ui.afterClearSearch = dash.run('filteredCves.map(c => c.id)');

  filterIds(dash, '');
  dash.resetUuid();
  out.exports.csv = dash.run('toCsv(filteredCves)');
  out.exports.json = dash.run('JSON.stringify(filteredCves, null, 2)');
  dash.resetUuid();
  out.exports.stix = JSON.parse(JSON.stringify(dash.run('toStixBundle(filteredCves)')));
  dash.resetUuid();
  out.exports.btnCsv = capture(dash, "exportData('csv')");
  out.exports.btnJson = capture(dash, "exportData('json')");
  dash.resetUuid();
  out.exports.btnStix = capture(dash, "exportData('stix')");
  filterIds(dash, "activeFilters.month = '2026-09';");
  out.exports.highRiskMonth = capture(dash, 'exportHighRiskByMonth()');
  filterIds(dash, "activeFilters.day = '2026-08-02';");
  out.exports.highRiskDay = capture(dash, 'exportHighRiskByMonth()');
  filterIds(dash, "activeFilters.search = 'cvss:>=9';");
  out.exports.filteredCsv = dash.run('toCsv(filteredCves)');

  dash.run('renderStats()');
  for (const id of ['stat-total', 'stat-kev', 'stat-weapon', 'stat-poc', 'stat-ai', 'stat-24h-sub', 'updated-time']) {
    out.stats[id] = dash.el(id).textContent;
  }
  out.stats.severity = dash.el('severity-dist').innerHTML;
  out.stats.products = dash.el('product-dist').innerHTML;
  out.stats.topProducts = JSON.parse(JSON.stringify(dash.run('computeTopProducts()')));
  out.stats.kpi = dash.run("KPI_TILES.map(sig => allCves.filter(c => cveHasSignal(c, sig)).length)");
  dash.run('buildVendorFilter(); buildProductFilter(); buildMonthFilter(); buildDayFilter();');
  for (const id of ['vendor-filter', 'product-filter', 'month-filter']) {
    out.stats[id] = dash.el(id).options.map(o => [o.value, o.textContent]);
  }
  out.stats['day-filter'] = dash.el('day-filter').innerHTML;

  filterIds(dash, '');
  for (const id of ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0005', 'CVE-2026-0012']) {
    dash.run(`showDetail(${JSON.stringify(id)})`);
    out.detail[id] = {
      id: dash.el('modal-id').textContent, title: dash.el('modal-title').textContent,
      sev: dash.el('modal-sev-badge').innerHTML, signals: dash.el('modal-signals').innerHTML,
      scores: dash.el('modal-scores').innerHTML, body: dash.el('modal-body').innerHTML,
    };
  }

  const bulk = dash.run('__fx.cves').flatMap((c, i) =>
    Array.from({ length: 8 }, (_, k) => Object.assign({}, c, { id: `CVE-2025-${String(i * 8 + k + 1).padStart(5, '0')}` })));
  dash.ctx.__bulk = bulk;
  dash.run('__saved = allCves; allCves = __bulk;');
  filterIds(dash, '');
  out.ui.bulkPage1 = { info: dash.el('page-info').textContent, rows: rowIds(dash.el('cve-table-body').innerHTML),
                       prevDisabled: dash.el('prev-btn').disabled, nextDisabled: dash.el('next-btn').disabled };
  dash.run('changePage(1)');
  out.ui.bulkPage2 = { info: dash.el('page-info').textContent, rows: rowIds(dash.el('cve-table-body').innerHTML) };
  dash.run('changePage(5)');
  out.ui.bulkLast = { info: dash.el('page-info').textContent, rows: rowIds(dash.el('cve-table-body').innerHTML),
                      nextDisabled: dash.el('next-btn').disabled };
  dash.run('changePage(-99)');
  out.ui.bulkBack = { info: dash.el('page-info').textContent, prevDisabled: dash.el('prev-btn').disabled };
  dash.run('allCves = __saved;');
  return out;
}

module.exports = { SEARCHES, FILTERS, SORTS, collect, rowIds };
