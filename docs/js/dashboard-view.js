/* 대시보드 — 주요 지표 6칸 → 최근 동향 카드 3장 → 신호 조합(2/3) · 30일 공개 추이(1/3) → 접어 둔 표(전체 조합 · 심각도 · 제품 · 최근 공개).
   화면의 숫자는 누르면 같은 조건의 CVE 목록이 열리고, 그 목록의 건수와 같다. 여러 신호를 합친 위험 점수는 만들지 않는다.
   전체 데이터(cves.json)가 오기 전에는 CI 사전 계산(cve-context.json)으로 먼저 그리고, 오면 다시 센다.
   값의 정의는 viewmodel.js, 판정 규칙은 context.js 한 곳에 있다. */

let dashAggregate = null;

function aggregateDays() {
  return CTX ? CTX.trendDays(statsData && statsData.generated_at, 30) : [];
}

function liveAggregate() {
  const key = `${lcToday}|${allCves.length}|${(statsData && statsData.generated_at) || ''}|${ctxVersion}`;
  if (dashAggregate && dashAggregate.key === key) return dashAggregate.value;
  const items = allCves.map(cve => CTX.aggregateItem(cve, cveContext(cve), lifecycleData ? cveLifecycle(cve) : null));
  const value = CTX.aggregate(items, { days: aggregateDays() });
  dashAggregate = { key, value };
  return value;
}

function precomputedUsable() {
  if (!contextData || !contextData.stats || !CTX || !statsData || !statsData.cve) return false;
  return contextData.inputs && contextData.inputs.cves === `${statsData.generated_at || ''}|${statsData.cve.total || 0}`;
}

function dashSource() {
  if (!CTX) return null;
  if (dataReady && allCves.length) return { live: true, stats: liveAggregate(), asOf: lcToday };
  if (precomputedUsable()) return { live: false, stats: contextData.stats, asOf: contextData.as_of };
  return null;
}

const fmt = n => (Number(n) || 0).toLocaleString();
const pct = (n, d) => (d ? `${((n / d) * 100).toFixed(1)}%` : '–');
// 한 줄에 들어갈 짧은 비율 — 0 보다 크면 0% 로 적지 않는다.
const pctShort = (n, d) => (!d ? '' : n > 0 && n / d < 0.005 ? '1% 미만' : `${Math.round((n / d) * 100)}%`);

// 한 번 그리는 동안 같은 검색어는 한 번만 센다(카드 · KPI 가 같은 검색어를 쓴다).
let dashQueryCache = null;
function dashQuery(q) {
  if (!dashQueryCache) return queryList(q);
  if (!dashQueryCache.has(q)) dashQueryCache.set(q, queryList(q));
  return dashQueryCache.get(q);
}

function renderDashboard() {
  const src = dashSource();
  dashQueryCache = dataReady && allCves.length ? new Map() : null;
  try {
    renderDashMeta(src);
    renderToday();
    renderKpis(src);
    renderCorrelations(src);
    renderOverview(src);
    renderRecent(src);
    renderHot();
    renderMatrix(src);
    renderFoldSums(src);
  } finally {
    dashQueryCache = null;
  }
}

function bindQueries(box) {
  box.querySelectorAll('[data-query]').forEach(b => b.addEventListener('click', () => goToQuery(b.dataset.query)));
}

// 데이터를 만든 시각 — '9월 28일 오전 9:55' 처럼 읽기 쉬운 형식(보는 사람의 시간대).
function dataTime() {
  const gen = new Date((statsData && statsData.generated_at) || '');
  return isNaN(gen) ? '' : gen.toLocaleString('ko-KR', { month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function renderDashMeta(src) {
  const when = dataTime();
  const total = (statsData && statsData.cve && statsData.cve.total) || allCves.length;
  const asof = byId('dash-asof');
  if (asof) asof.textContent = when ? `${when} 기준 · 추적 중 CVE ${fmt(total)}건` : '';
  const el = byId('dash-meta');
  if (!el) return;
  const how = !src ? '집계를 준비하는 중'
    : src.live ? `브라우저에서 계산 (${contextValid ? 'CI가 만든 제품 연결 사용' : 'CI 결과가 없거나 달라 제품을 직접 연결'})`
    : 'CI 사전 계산 값 (전체 데이터를 받으면 다시 계산)';
  el.innerHTML = `CVE 기준 <b>${escapeHtml(when || '-')}</b> · 수명주기 기준일 <b>${escapeHtml(src ? src.asOf : '-')}</b> · ${escapeHtml(how)}`;
}

/* ---------- 최근 동향 — 카드마다 검색어 하나. 숫자 = 그 검색어로 연 목록 건수 ---------- */

const TODAY_ROWS = 3;
const todayLists = {};
let evidenceWait = false;

// CISA KEV 등재일은 cve-evidence.json 에만 있다. 처음 필요할 때 받고, 받으면 카드와 KPI 를 다시 그린다.
function kevDatesReady() {
  if (detailFiles.evidence !== undefined) return true;
  if (!evidenceWait && typeof loadAuxFile === 'function') {
    evidenceWait = true;
    loadAuxFile('evidence').then(() => {
      if (detailFiles.evidence === undefined) return;  // 받을 수 없는 환경 — 다시 부르지 않는다
      evidenceWait = false;
      if (currentView === 'dashboard') { renderToday(); renderKpis(dashSource()); }
    });
  }
  return false;
}

// 날짜 한 칸 — 기준일과 같은 해면 월-일만.
function shortDay(iso) {
  const d = String(iso || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return '';
  return d.slice(0, 4) === refDay().slice(0, 4) ? d.slice(5) : d;
}

const byCvssDesc = (a, b) => (Number(b.cvss) || 0) - (Number(a.cvss) || 0)
  || (Date.parse(b.date || '') || 0) - (Date.parse(a.date || '') || 0);

function todayCards() {
  const kevReady = kevDatesReady();
  const threatChips = (r, skip) => (r.threat || []).filter(t => t.kind !== skip).slice(0, 2)
    .map(t => evChip(t.kind, t.label, t.title, t.extra)).join('');
  return [
    {
      key: 'kev', title: 'KEV 신규 등재', span: '최근 7일', query: 'kev:7d', order: '등재일 순',
      wait: !kevReady ? '등재일 정보를 받는 중…'
        : detailFiles.evidence === null ? 'KEV 등재일 정보(cve-evidence.json)를 받지 못해 셀 수 없습니다.' : '',
      fallback: { query: 'has:cisa-kev', text: 'CISA KEV 전체 보기' },
      sort: (a, b) => kevAddedOf(b).localeCompare(kevAddedOf(a)) || byCvssDesc(a, b),
      // KEV 조치 기한은 미국 연방 민간기관의 기한이라 줄마다 적지 않는다(등재일만). 머리 링크는 누구의 기한인지 이름에 적는다.
      basis: () => `CISA 등재일 기준 · <button type="button" class="t-link" data-query="due:3d"
          title="미국 연방 민간기관의 KEV 조치 기한이 데이터 기준일부터 3일 안인 CVE. 다른 기관 · 기업의 의무 기한은 아닙니다">미 연방기관 기한 3일 안 ${fmt(dashQuery('due:3d').length)}건</button>`,
      right: c => `<span class="t-key">등재 ${escapeHtml(shortDay(kevAddedOf(c)))}</span>`,
      empty: '최근 7일 안에 새로 등재된 CVE가 없습니다.',
    },
    {
      key: 'crit', title: '최근 24시간 Critical', span: '', query: 'recent:24h sev:critical', order: 'CVSS 순',
      wait: '', sort: byCvssDesc,
      basis: () => `알림·갱신 ${fmt(dashQuery('recent:24h').length)}건 중 · Argus 알림 시각 기준`,
      right: (c, r) => `<span class="t-opt">${threatChips(r)}</span><span class="t-key">공개 ${escapeHtml(shortDay(c.published) || '-')}</span>`,
      empty: '최근 24시간 안에 알림·갱신된 Critical CVE가 없습니다.',
    },
    {
      key: 'exp', title: '공개 익스플로잇이 나온 새 CVE', span: '최근 7일', query: 'published:7d has:exploit', order: 'CVSS 순',
      wait: CTX ? '' : '판단 모듈(context.js)을 불러오지 못해 셀 수 없습니다.', sort: byCvssDesc,
      basis: () => `최근 7일 공개 ${fmt(dashQuery('published:7d').length)}건 중 · Exploit-DB · Metasploit · PoC`,
      right: (c, r) => `<span class="t-opt">${threatChips(r, 'weapon')}</span><span class="t-key">공개 ${escapeHtml(shortDay(c.published) || '-')}</span>`,
      empty: '최근 7일 안에 공개된 CVE 중에는 없습니다.',
    },
  ];
}

function todayRowHtml(c, card) {
  const r = listRowOf(c);
  const score = r.cvss ? ` ${r.cvss.text}` : '';
  return `<li><button type="button" class="t-row" data-cve="${escapeHtml(c.id)}" title="${escapeHtml(r.title)}">
    <span class="t-l1"><span class="cve-id">${escapeHtml(c.id)}</span><span class="badge badge-sev sev-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}${score}</span><span class="t-right">${card.right(c, r)}</span></span>
    <span class="t-l2">${r.product.name ? `<b>${escapeHtml(r.product.name)}</b> · ` : ''}${escapeHtml(r.title)}</span>
  </button></li>`;
}

function renderToday() {
  const box = byId('dash-today');
  if (!box) return;
  const cards = todayCards();
  const ready = dataReady && allCves.length;
  box.innerHTML = cards.map(card => {
    const head = n => `<header class="t-head"><h2>${escapeHtml(card.title)}</h2>${card.span ? `<span class="t-span">${escapeHtml(card.span)}</span>` : ''}${
      n === null ? '' : `<button type="button" class="t-n" data-query="${escapeHtml(card.query)}" title="누르면 목록이 열립니다 (${escapeHtml(card.query)})">${fmt(n)}</button>`}</header>`;
    if (!ready || card.wait) {
      const text = card.wait || (loadFailed ? '데이터를 불러오지 못했습니다.' : '불러오는 중…');
      const alt = card.wait && card.fallback && ready && !/받는 중/.test(card.wait)
        ? `<footer class="t-foot"><button type="button" class="t-all" data-query="${escapeHtml(card.fallback.query)}">${escapeHtml(card.fallback.text)} →</button></footer>` : '';
      delete todayLists[card.key];
      return `<article class="t-card t-${card.key}" data-card="${card.key}">${head(null)}<p class="t-wait">${escapeHtml(text)}</p>${alt}</article>`;
    }
    const list = dashQuery(card.query).slice().sort(card.sort);
    todayLists[card.key] = { label: card.title, ids: list.map(c => c.id) };
    const rows = list.slice(0, TODAY_ROWS).map(c => todayRowHtml(c, card)).join('');
    return `<article class="t-card t-${card.key}" data-card="${card.key}">${head(list.length)}
      <p class="t-basis">${card.basis()}</p>
      ${rows ? `<ol class="t-rows">${rows}</ol>` : `<p class="t-wait">${escapeHtml(card.empty)}</p>`}
      ${list.length ? `<footer class="t-foot"><button type="button" class="t-all" data-query="${escapeHtml(card.query)}">${fmt(list.length)}건 모두 보기 →</button><span class="t-order">${escapeHtml(card.order)}</span></footer>` : ''}
    </article>`;
  }).join('');
  bindQueries(box);
  box.querySelectorAll('[data-cve]').forEach(b => b.addEventListener('click', () => {
    const card = b.closest('[data-card]');
    const ctx = card ? todayLists[card.dataset.card] : null;
    openCveFrom(b.dataset.cve, ctx ? { label: ctx.label, ids: ctx.ids.slice() } : null);
  }));
}

/* ---------- 주요 지표 6칸 — 숫자 = 누르면 열리는 목록 건수 ---------- */

// 숫자 아래 줄의 변화량 — 전체 데이터가 있어야 셀 수 있다. KEV 등재일은 cve-evidence.json 을 받은 뒤에.
function kpiExtra() {
  if (!dataReady || !allCves.length) return null;
  const recent = dashQuery('recent:24h');
  return {
    published7: dashQuery('published:7d').length,
    kevAdded7: detailFiles.evidence ? dashQuery('kev:7d').length : null,
    recentCritical: recent.filter(c => (c.severity || 'None') === 'Critical').length,
    recentKev: recent.filter(c => c.is_kev).length,
    ai7: dashQuery('published:7d has:ai').length,
  };
}

function renderKpis(src) {
  const box = byId('dash-kpis');
  if (!box || !VM) return;
  const s = (statsData && statsData.cve) || {};
  box.innerHTML = VM.kpis(src ? src.stats : null, statsData, kpiExtra()).map(k => {
    const value = k.id === 'stat-total' ? (s.total || allCves.length)
      : (() => { const n = kpiCount(k.id); return n !== null ? n : k.value; })();
    const sub = k.delta
      ? `<span class="kpi-sub">${k.delta.n > 0 ? `<b class="kpi-up">+${fmt(k.delta.n)}</b> ${escapeHtml(k.delta.text)}` : `${escapeHtml(k.delta.text)} 없음`}</span>`
      : `<span class="kpi-sub">${escapeHtml(k.line || '')}</span>`;
    const go = k.query ? `누르면 목록이 열립니다 (${k.query})` : '누르면 전체 목록이 열립니다';
    return `<button type="button" class="kpi kpi-link${k.group ? ` g-${k.group}` : ''}" data-query="${escapeHtml(k.query)}" title="${escapeHtml(`${k.title}. ${go}`)}">
      <span class="kpi-label">${escapeHtml(k.label)}</span>
      <span class="kpi-value" id="${k.id}">${value === null || value === undefined ? '-' : fmt(value)}</span>
      ${sub}
    </button>`;
  }).join('');
  bindQueries(box);
}

/* ---------- 신호 조합 — 두 신호가 함께 확인된 CVE 수, 많은 순 ---------- */

const PART_GROUP = {
  CISA_KEV: 'exploit', EXPLOITATION_CONFIRMED: 'exploit', RANSOMWARE: 'exploit', PUBLIC_EXPLOIT: 'weapon',
  AUTOMATABLE: 'auto', EOL_AFFECTED: 'lifecycle', PATCH_AVAILABLE: 'defense', PUBLIC_DETECTION: 'defense',
  HIGH_EPSS: 'score', CRITICAL_CVSS: 'sev',
};

function partLabel(p) {
  const sig = CTX.SIGNAL[p.code];
  const label = p.negated && p.code === 'PATCH_AVAILABLE' ? '수정 기록 없음' : p.negated ? `${sig.short} 없음` : sig.short;
  return `<span class="corr-part g-${PART_GROUP[p.code] || 'src'}"><i></i>${escapeHtml(label)}</span>`;
}

function renderCorrelations(src) {
  const box = byId('dash-corr');
  if (!box) return;
  if (!src || !VM) { box.innerHTML = '<li class="dash-wait">불러오는 중…</li>'; return; }
  const list = VM.correlations(src.stats);
  const max = Math.max(1, ...list.map(c => c.n));
  box.innerHTML = list.map(c => {
    const scope = c.share !== null ? `${c.scopeText} ${pctShort(c.n, c.scope)}` : c.scopeText;
    return `<li><button type="button" class="corr-card${c.n ? '' : ' is-zero'}" data-query="${escapeHtml(c.query)}"
      title="${escapeHtml(`${c.label}. ${c.scopeTitle ? `${c.scopeTitle}. ` : ''}누르면 목록이 열립니다 (${c.query})`)}">
    <span class="corr-parts">${partLabel(c.parts[0])}<em>×</em>${partLabel(c.parts[1])}</span>
    <span class="corr-track" aria-hidden="true"><span style="width:${(c.n / max * 100).toFixed(1)}%"></span></span>
    <span class="corr-n">${fmt(c.n)}</span>
    <span class="corr-scope">${escapeHtml(scope)}</span>
  </button></li>`;
  }).join('');
  bindQueries(box);
}

/* ---------- 30일 공개 추이 — 공개일별 건수 한 계열(선 · 면), 칸마다 심각도 내역 ---------- */

let overviewModel = null;

function renderOverview(src) {
  const box = byId('dash-overview');
  if (!box) return;
  if (!src || !VM) { box.innerHTML = '<p class="dash-wait">불러오는 중…</p>'; return; }
  const ov = VM.overview(src.stats);
  overviewModel = ov;
  if (!ov.days.length) { box.innerHTML = '<p class="dash-wait">일별 집계가 없습니다.</p>'; return; }
  const n = ov.days.length;
  const peak = ov.totals.reduce((a, t, i) => (t > ov.totals[a] ? i : a), 0);
  const s = (statsData && statsData.cve) || {};
  const md = iso => iso.slice(5).replace('-', '.');
  // 선은 SVG 로 늘려 그리고(선 굵기는 고정), 최댓값 점은 HTML 로 올려 둥근 모양을 지킨다.
  const W = 300, H = 72, PAD = 4;
  const x = i => (n === 1 ? W / 2 : PAD + (i * (W - PAD * 2)) / (n - 1));
  const y = v => H - PAD - (v / ov.max) * (H - PAD * 2);
  const line = ov.totals.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
  const area = `${line}L${x(n - 1).toFixed(1)},${H - PAD}L${x(0).toFixed(1)},${H - PAD}Z`;
  const cols = ov.days.map((d, i) => `<div class="ov-col${ov.totals[i] ? '' : ' is-empty'}" data-i="${i}"></div>`).join('');
  const covered = typeof s.trend_covered === 'number' && s.total && s.trend_covered < s.total
    ? `<p class="ov-note">공개일이 확인된 ${fmt(s.trend_covered)}건 기준 (전체 ${fmt(s.total)}건)</p>` : '';
  const rows = ov.days.map((d, i) => `<tr><td>${escapeHtml(d.date)}</td><td><b>${fmt(ov.totals[i])}</b></td>${
    ['Critical', 'High', 'Medium', 'Low', 'None'].map(k => `<td>${fmt(d[k])}</td>`).join('')}</tr>`).reverse().join('');
  box.innerHTML = `
    <p class="ov-sum">합계 <b>${fmt(ov.sum)}</b>건 · 하루 최대 <b>${fmt(ov.totals[peak])}</b>건(${escapeHtml(md(ov.days[peak].date))}) · 최근 7일 <b>${fmt(ov.last7)}</b>건</p>
    <div class="ov-chart" role="img" aria-label="${escapeHtml(`최근 30일 CVE 공개일별 건수. 합계 ${fmt(ov.sum)}건, 하루 최대 ${fmt(ov.totals[peak])}건. 날짜별 숫자는 아래 표로 보기에 있습니다`)}">
      <svg class="ov-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">
        <line class="ov-base" x1="0" x2="${W}" y1="${H - PAD}" y2="${H - PAD}"/>
        <path class="ov-area" d="${area}"/><path class="ov-line" d="${line}"/>
      </svg>
      <span class="ov-peak" aria-hidden="true" style="left:${(x(peak) / W * 100).toFixed(2)}%;top:${(y(ov.totals[peak]) / H * 100).toFixed(2)}%"></span>
      <div class="ov-hit">${cols}</div>
    </div>
    <div class="ov-x" aria-hidden="true"><span>${escapeHtml(md(ov.days[0].date))}</span><span>${escapeHtml(md(ov.days[n - 1].date))}</span></div>
    ${covered}
    <details class="ov-table"><summary>표로 보기</summary>
      <div class="table-scroll"><table class="d-table"><thead><tr><th>공개일</th><th>합계</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>점수 없음</th></tr></thead><tbody>${rows}</tbody></table></div>
    </details>`;
  const colsEl = box.querySelector('.ov-hit');
  if (colsEl) {
    colsEl.addEventListener('pointermove', e => {
      const col = e.target.closest('.ov-col');
      if (col) showOverviewTip(col, e);
    });
    colsEl.addEventListener('pointerleave', hideVizTip);
  }
}

function vizTip() {
  let tip = byId('viz-tip');
  if (!tip) {
    tip = document.createElement('div');
    tip.id = 'viz-tip';
    tip.className = 'viz-tip';
    tip.hidden = true;
    document.body.appendChild(tip);
  }
  return tip;
}

function hideVizTip() {
  const tip = byId('viz-tip');
  if (tip) tip.hidden = true;
  document.querySelectorAll('.ov-col.is-hot').forEach(c => c.classList.remove('is-hot'));
}

function showOverviewTip(col, e) {
  const ov = overviewModel;
  const i = Number(col.dataset.i);
  if (!ov || !ov.days[i]) return;
  const d = ov.days[i];
  document.querySelectorAll('.ov-col.is-hot').forEach(c => c.classList.remove('is-hot'));
  col.classList.add('is-hot');
  const tip = vizTip();
  tip.innerHTML = `<div class="tip-head">${escapeHtml(d.date)} 공개 <b>${fmt(ov.totals[i])}</b>건</div>${
    [['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low'], ['None', '점수 없음']]
      .filter(([k]) => d[k]).map(([k, l]) => `<div class="tip-row"><span>${l}</span><b>${fmt(d[k])}</b></div>`).join('')}`;
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  const x = Math.min(window.innerWidth - r.width - 8, e.clientX + 14);
  const y = e.clientY - r.height - 12 < 8 ? e.clientY + 16 : e.clientY - r.height - 12;
  tip.style.left = `${Math.max(8, x)}px`;
  tip.style.top = `${y}px`;
}

/* ---------- 최근 공개 CVE — 공개일 순 (접어 둔 칸) ---------- */

let recentIds = [];

function renderRecent(src) {
  const box = byId('dash-recent');
  if (!box) return;
  let list = null;
  if (dataReady && allCves.length && CTX) list = CTX.recentOf(allCves, cveContext, 8);
  else if (precomputedUsable() && Array.isArray(contextData.recent)) list = contextData.recent;
  if (!list || !VM) { box.innerHTML = '<li class="dash-wait">불러오는 중…</li>'; recentIds = []; return; }
  const items = VM.recent(list, statsData && statsData.generated_at);
  recentIds = items.map(r => r.id);
  box.innerHTML = items.map(r => `<li><button type="button" class="recent-item" data-cve="${escapeHtml(r.id)}" title="${escapeHtml(r.title)}">
    <span class="r-top"><span class="cve-id">${escapeHtml(r.id)}</span><span class="badge badge-sev sev-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}${r.cvss ? ` ${r.cvss.toFixed(1)}` : ''}</span><span class="r-ago">${escapeHtml(r.ago || r.published)}</span></span>
    <span class="r-title">${escapeHtml(r.title)}</span>
    ${r.signalLabels.length ? `<span class="r-sig">${r.signals.filter(k => k !== 'EXPLOITATION_CONFIRMED' || !r.signals.includes('CISA_KEV'))
      .map(k => `<span class="g-${PART_GROUP[k] || 'src'}"><i class="sig-dot"></i>${escapeHtml(CTX.SIGNAL[k].short)}</span>`).join('')}</span>` : ''}
  </button></li>`).join('') || '<li class="dash-wait">최근 공개된 CVE가 없습니다.</li>';
  box.querySelectorAll('[data-cve]').forEach(b => b.addEventListener('click', () =>
    openCveFrom(b.dataset.cve, { label: '최근 공개 CVE', ids: recentIds.slice() })));
}

/* ---------- 화제 CVE — 공개 90일 이내, 공개 PoC 저장소가 많은 순 (접어 둔 칸) ---------- */

let hotIds = [];
const HOT_WINDOW = '90d';

// 화제 정도(공개 PoC 저장소 수 — export 가 그때의 PoC 색인에서 센 값)이며 악용 근거는 아니다.
// 공개일 창은 검색어 published:90d 와 같은 기준(데이터 기준일 포함 90일). 같은 수면 최근 공개 순.
function hotCves(cves, n) {
  return (cves || []).filter(c => Number(c.poc_count) > 0 && withinDays(c.published, HOT_WINDOW))
    .sort((a, b) => (Number(b.poc_count) - Number(a.poc_count))
      || String(b.published || '').localeCompare(String(a.published || ''))
      || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .slice(0, n || 8);
}

function renderHot() {
  const box = byId('dash-hot');
  if (!box) return;
  if (!dataReady || !allCves.length) { box.innerHTML = '<li class="dash-wait">불러오는 중…</li>'; hotIds = []; return; }
  const items = hotCves(allCves, 8);
  hotIds = items.map(c => c.id);
  box.innerHTML = items.map(c => {
    const sev = c.severity || 'None';
    const cvss = Number(c.cvss) || 0;
    return `<li><button type="button" class="recent-item" data-cve="${escapeHtml(c.id)}" title="${escapeHtml(c.title || '')}">
    <span class="r-top"><span class="cve-id">${escapeHtml(c.id)}</span>${nicknameTagHtml(c.nicknames, c.poc_count)}<span class="badge badge-sev sev-${escapeHtml(sev)}">${escapeHtml(sev)}${cvss ? ` ${cvss.toFixed(1)}` : ''}</span><span class="r-ago">PoC 저장소 ${fmt(c.poc_count)}개</span></span>
    <span class="r-title">${escapeHtml(c.title || '')}</span>
  </button></li>`;
  }).join('') || '<li class="dash-wait">공개 90일 이내에 PoC가 올라온 CVE가 없습니다.</li>';
  box.querySelectorAll('[data-cve]').forEach(b => b.addEventListener('click', () =>
    openCveFrom(b.dataset.cve, { label: '화제 CVE', ids: hotIds.slice() })));
}

/* ---------- 전체 조합 표 + 많이 겹치는 조합 (접어 둔 칸) ---------- */

// 순차 램프 5단계 — 경계는 최댓값의 (k/5)² (작은 값이 한 칸에 몰리지 않게). 칸에는 실제 건수를 적는다.
function matrixBins(max) {
  const edges = [];
  for (let k = 1; k <= 5; k++) edges.push(Math.max(1, Math.ceil(max * (k / 5) ** 2)));
  return edges;
}
const binOf = (n, edges) => (n <= 0 ? 0 : edges.findIndex(e => n <= e) + 1 || 5);

function renderMatrix(src) {
  const box = byId('dash-matrix');
  const chips = byId('dash-rel-chips');
  if (!box) return;
  const mx = src && VM ? VM.matrix(src.stats) : null;
  if (!mx) { box.innerHTML = '<p class="dash-wait">불러오는 중…</p>'; if (chips) chips.innerHTML = ''; return; }
  const edges = matrixBins(mx.max);
  const ax = mx.axes;
  // 줄 · 칸 머리에 그 신호 전체('있음') 건수. 누르면 그 신호 전체 목록.
  const axisBtn = a => `<button type="button" class="mx-row" data-query="${escapeHtml(a.query)}"
      title="${escapeHtml(`${a.short} 전체 ${fmt(a.total)}건. 누르면 목록이 열립니다 (${a.query})`)}">${escapeHtml(a.short)}<small>${fmt(a.total)}</small></button>`;
  const head = `<tr><th></th>${ax.slice(1).map(a => `<th scope="col" title="${escapeHtml(CTX.SIGNAL[a.code].def)}">${axisBtn(a)}</th>`).join('')}</tr>`;
  const body = ax.slice(0, -1).map((a, i) => `<tr><th scope="row">${axisBtn(a)}</th>${
    ax.slice(1).map((b, jj) => {
      const j = jj + 1;
      if (j <= i) return '<td></td>';
      const c = mx.cells[`${i}|${j}`];
      const bin = binOf(c.n, edges);
      const label = `${a.short} × ${b.short}: 함께 있음 ${fmt(c.n)}건`;
      return c.n
        ? `<td><button type="button" class="mx-cell mx-${bin}" data-query="${escapeHtml(c.query)}" title="${escapeHtml(`${label}. 누르면 목록이 열립니다`)}" aria-label="${escapeHtml(label)}">${fmt(c.n)}</button></td>`
        : `<td><span class="mx-cell mx-0" title="${escapeHtml(label)}">0</span></td>`;
    }).join('')}</tr>`).join('');
  const ranges = edges.map((e, k) => [k === 0 ? 1 : edges[k - 1] + 1, e]).filter(([lo, hi]) => lo <= hi);
  box.innerHTML = `<p class="mx-hint">옆으로 밀면 나머지 칸이 보입니다</p><table class="matrix"><thead>${head}</thead><tbody>${body}</tbody></table>
    <div class="mx-legend"><span>색이 진할수록 많음</span>${
      ranges.map(([lo, hi]) => `<span><i class="mx-${edges.indexOf(hi) + 1}"></i>${fmt(lo)}${hi > lo ? `–${fmt(hi)}` : ''}</span>`).join('')}</div>`;
  bindQueries(box);
  if (chips) {
    const pairs = Object.entries(mx.cells).filter(([, c]) => c.n > 0).sort((p, q) => q[1].n - p[1].n).slice(0, 6);
    chips.innerHTML = pairs.map(([key, c]) => {
      const [i, j] = key.split('|').map(Number);
      const name = `${ax[i].short} × ${ax[j].short}`;
      return `<button type="button" class="rel-chip" data-query="${escapeHtml(c.query)}" title="${escapeHtml(`${name}. 누르면 목록이 열립니다`)}"><span class="rel-name">${escapeHtml(name)}</span><code>${escapeHtml(c.query)}</code><b>${fmt(c.n)}</b></button>`;
    }).join('') || '<p class="dash-wait">함께 있는 조합이 없습니다.</p>';
    bindQueries(chips);
  }
}

/* ---------- 접어 둔 칸 — 버튼 옆 요약 · 열고 닫기 ---------- */

function renderFoldSums(src) {
  const put = (id, text) => { const el = byId(id); if (el) el.textContent = text; };
  const mx = src && VM ? VM.matrix(src.stats) : null;
  put('fold-combos-sum', mx ? `${Math.min(6, Object.values(mx.cells).filter(c => c.n > 0).length)}개` : '');
  const sev = (statsData && statsData.cve && statsData.cve.severity) || null;
  put('fold-sev-sum', sev ? `Critical ${fmt(sev.Critical)} · High ${fmt(sev.High)}` : '');
  const tops = (statsData && statsData.cve && statsData.cve.top_products) || [];
  const top = tops.length ? tops[0] : (dataReady && allCves.length ? computeTopProducts(1)[0] : null);
  put('fold-products-sum', top ? `${top.product} ${fmt(top.count)} …` : '');
  put('fold-recent-sum', recentIds.length ? `${recentIds.length}건` : '');
  const hot = hotIds.length ? allCves.find(c => c.id === hotIds[0]) : null;
  put('fold-hot-sum', hot ? `${(hot.nicknames || [])[0] || hot.id} ${fmt(hot.poc_count)} …` : '');
}

function toggleFold(btn) {
  const panel = byId(btn.getAttribute('aria-controls'));
  if (!panel) return;
  const open = panel.hidden;
  panel.hidden = !open;
  btn.setAttribute('aria-expanded', String(open));
  btn.classList.toggle('is-open', open);
  if (open && typeof panel.scrollIntoView === 'function') panel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.fold-btn').forEach(b => b.addEventListener('click', () => toggleFold(b)));
});
