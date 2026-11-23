'use strict';
// 브라우저 없이 docs/js/*.js 를 그대로 실행한다. DOM 은 값만 받아 두는 가짜 요소로 대신한다.
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURES = path.join(ROOT, 'tests', 'fixtures');

function fakeElement(tag, id) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(), id: id || '', innerHTML: '', textContent: '', value: '',
    hidden: false, disabled: false, checked: false, title: '', style: {}, dataset: {}, options: [], children: [],
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    appendChild(child) {
      this.children.push(child);
      if (child && child.tagName === 'OPTION') this.options.push(child);
      return child;
    },
    addEventListener() {}, removeEventListener() {}, setAttribute() {}, getAttribute() { return null; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    scrollIntoView() {}, closest() { return null; }, remove() {}, click() {}, focus() {},
  };
  return el;
}

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf8'));
}

// 날짜의 로캘 표기는 ICU/CLDR 판마다 다르다 — 실측: Node 22.22.2 '26. 9. 27. AM 3:00', 22.23.3 '26. 9. 27. 오전 3:00'.
// 회귀 기준이 Node 판을 타지 않도록 표기 결과 대신 '어떤 시각을 어떤 로캘·옵션으로 표기하라고 했는지'를 남긴다.
const localeCall = (name, d, locales, options) =>
  `${name}(${JSON.stringify(locales === undefined ? null : locales)},${JSON.stringify(options === undefined ? null : options)})@${isNaN(d) ? 'Invalid Date' : d.toISOString()}`;

class HermeticDate extends Date {
  toLocaleString(locales, options) { return localeCall('toLocaleString', this, locales, options); }
  toLocaleDateString(locales, options) { return localeCall('toLocaleDateString', this, locales, options); }
  toLocaleTimeString(locales, options) { return localeCall('toLocaleTimeString', this, locales, options); }
}

function loadDashboard(sources) {
  const elements = new Map();
  let uuid = 0;
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, fakeElement('div', id));
      return elements.get(id);
    },
    createElement(tag) { return fakeElement(tag); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    addEventListener() {},
    body: fakeElement('body'),
    documentElement: fakeElement('html'),
    execCommand() { return true; },
  };
  const store = new Map();
  const localStorage = {
    getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => { store.set(k, String(v)); },
    removeItem: k => { store.delete(k); },
  };
  const ctx = {
    document, console, URL, Date: HermeticDate, Math, JSON, Map, Set, WeakMap, Promise, RegExp, Number, String, Array, Object,
    setTimeout: fn => { fn(); return 0; }, clearTimeout() {},
    location: { href: 'https://example.test/cve.html', origin: 'https://example.test', pathname: '/cve.html', search: '' },
    history: { last: null, replaceState(state, title, url) { this.last = String(url); } },
    alert() {}, scrollTo() {}, addEventListener() {}, localStorage, innerWidth: 1280, innerHeight: 800,
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    navigator: {},
    crypto: {
      randomUUID: () => `00000000-0000-4000-8000-${String(++uuid).padStart(12, '0')}`,
      getRandomValues: arr => arr.fill(7),
    },
    Blob: function Blob(parts, opts) { this.parts = parts; this.opts = opts; },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  for (const src of sources) {
    const code = src.code != null ? src.code : fs.readFileSync(path.join(ROOT, src.file), 'utf8');
    vm.runInContext(code, ctx, { filename: src.file || src.name || 'inline.js' });
  }
  const run = code => vm.runInContext(code, ctx);
  return { ctx, run, elements, el: id => document.getElementById(id), resetUuid() { uuid = 0; } };
}

const RESET = `
  activeFilters = {
    severity: new Set(['Critical', 'High', 'Medium', 'Low', 'None']),
    search: '', vendor: '', product: '', month: '', day: '',
    kernel: '', cvssMin: null, epssMin: null,
  };
  sortField = 'tier'; sortDir = 1; currentPage = 1;
`;

function withFixture(dash, extra = {}) {
  dash.ctx.__fx = Object.assign({
    cves: readJson('dashboard_cves.json'),
    stats: readJson('dashboard_stats.json'),
    packages: readJson('dashboard_packages.json').packages,
    products: readJson('dashboard_products.json'),
  }, extra);
  dash.run(`
    allCves = __fx.cves; statsData = __fx.stats; cvePackages = __fx.packages;
    setProductIndex(__fx.products);
  `);
  return dash;
}

function filterIds(dash, setup) {
  dash.run(RESET);
  if (setup) dash.run(setup);
  dash.run('applyFilters()');
  return dash.run('filteredCves.map(c => c.id)');
}

module.exports = { ROOT, FIXTURES, readJson, loadDashboard, withFixture, filterIds, RESET };
