// logic.js —— 读 dashboard/index.html → 提取嵌入 JSON → 白名单过滤 → mtime 缓存。
// 本文件是热更面：改完保存即在下一次请求生效（index.js 按 mtime 重 import）。
// 数据路径：优先环境变量 AIRMON_DASHBOARD（指向 index.html），否则用下面的默认值；
// 都读不到时回退包内 data.json 快照（响应标 _source:'snapshot'）。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_INDEX = 'E:/Hermes-Agent/Jichang-Monitor/dashboard/index.html';
const INDEX = process.env.AIRMON_DASHBOARD || DEFAULT_INDEX;
const SNAPSHOT = fileURLToPath(new URL('./data.json', import.meta.url));
// 节点详情数据源：data/<airport>/<YYYYMMDDTHHMMSSZ>.json（airmon.store 布局）
const DEFAULT_DATA = 'E:/Hermes-Agent/Jichang-Monitor/data';
const DATA_DIR = process.env.AIRMON_DATA || DEFAULT_DATA;
const SNAP_RE = /^\d{8}T\d{6}Z\.json$/;
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i;
// 节点白名单：绝不透出 raw（password/_rdap/_resolved_ips 等）与 source（可能含订阅 URL）
const NODE_KEYS = ['name', 'server', 'port', 'protocol', 'network', 'type'];

// ---- 白名单契约（与 docs/08-侧边栏插件方案.md §6.2 一一对应）----
const TOTAAL_KEYS = ['airports', 'dirs', 'with_nodes', 'nodes', 'hits',
  'zero_pull', 'stale', 'expiring30', 'expired'];
const AP_KEYS = ['slug', 'route', 'status', 'nodes', 'pull_zero', 'age_h',
  'latest_ts', 'latest_local', 'snap24', 'added_n', 'removed_n', 'no_prev',
  'hit_n', 'proto_top', 'expire', 'usage_pct', 'info'];
const QUOTA_KEYS = ['expire_date', 'days_left', 'total_gb', 'used_gb',
  'used_pct', 'unlimited'];
const ALERT_KEYS = ['ts', 'ts_local', 'airport', 'hw_n', 'added_n', 'removed_n'];
const RUN_KEYS = ['start_local', 'done_local', 'duration_min', 'final_aps',
  'final_nodes', 'ok_n', 'ok_nodes', 'ok_top', 'skipped', 'zero', 'auth',
  'inflight', 'note'];
const LEDGER_KEYS = ['airport', 'rule', 'evidence', 'count', 'last_ts_local'];

const pick = (d, keys) => {
  const o = {};
  for (const k of keys) if (d && d[k] !== undefined) o[k] = d[k];
  return o;
};

function extractEmbedded(html) {
  const blocks = html.match(/<script[^>]*>[\s\S]*?<\/script>/g) || [];
  const hit = blocks.reverse().find(b => b.includes('"airports"'));
  if (!hit) throw new Error('embedded JSON not found');
  const start = hit.indexOf('{');
  return JSON.parse(hit.slice(start, hit.lastIndexOf('}') + 1));
}

function geoTop(detail) {
  const cc = new Map();
  for (const n of (detail && detail.nodes) || []) {
    const c = n.c || '未知';
    cc.set(c, (cc.get(c) || 0) + 1);
  }
  return [...cc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
}

export function sanitize(data) {
  const airports = (data.airports || []).map(a => {
    const out = pick(a, AP_KEYS);
    out.geo_top = geoTop(a.detail);
    out.node_total = ((a.detail && a.detail.nodes) || []).length;
    // 节点行（dashboard _node_row 短键 {n,p,s,o,c}，已脱敏；弹窗直接渲染 + /api/nodes 回退）
    out.node_rows = ((a.detail && a.detail.nodes) || []).slice(0, 400).map(nd => {
      if (!nd || typeof nd !== 'object') return {};
      return {
        name: typeof nd.n === 'string' ? nd.n : '',
        server: typeof nd.s === 'string' ? nd.s : '',
        port: (typeof nd.o === 'number' || typeof nd.o === 'string') ? nd.o : '',
        protocol: typeof nd.p === 'string' ? nd.p : '',
        cc: typeof nd.c === 'string' ? nd.c : '',
        r: typeof nd.r === 'string' ? nd.r : '',
      };
    });
    if (a.quota) out.quota = pick(a.quota, QUOTA_KEYS);
    return out;
  });
  let totals = pick(data.totals || {}, TOTAAL_KEYS);
  if (totals.airports == null) {
    // 兜底重算（schema 漂移时卡片仍可用）
    totals = {
      airports: airports.length,
      dirs: airports.length,
      with_nodes: airports.filter(a => a.nodes > 0).length,
      nodes: airports.reduce((s, a) => s + (a.nodes || 0), 0),
      hits: airports.reduce((s, a) => s + (a.hit_n || 0), 0),
      zero_pull: airports.filter(a => a.pull_zero).map(a => a.slug),
      stale: airports.filter(a => a.status === 'stale').map(a => a.slug),
      expiring30: airports.filter(a => a.quota && a.quota.days_left != null
        && a.quota.days_left >= 0 && a.quota.days_left <= 30).map(a => a.slug),
      expired: airports.filter(a => a.quota && a.quota.days_left != null
        && a.quota.days_left < 0).map(a => a.slug),
    };
  }
  return {
    generated_at: data.generated_at,
    base_local: data.base_local,
    quota_at: data.quota_at,
    stale_hours: data.stale_hours,
    totals,
    airports,
    sites_free: loadSiteRows(SITEWATCH_FILE, SITE_KEYS),
    sites_digest: loadSiteRows(DIGEST_FILE, DIGEST_KEYS),
    analysis: loadAnalysis(),
    alerts: (data.alerts || []).map(x => pick(x, ALERT_KEYS)),
    hw_ledger: (data.hw_ledger || []).map(x => pick(x, LEDGER_KEYS)),
    hw_current: data.hw_current || [],
    runlog: pick(data.runlog || {}, RUN_KEYS),
  };
}

let cache = null; // { key, payload }

// ---- 分析页数据源：data/analysis.json（airmon.analyze 预计算，全聚合值）----
const ANALYSIS_FILE = process.env.AIRMON_ANALYSIS ||
  'E:/Hermes-Agent/Jichang-Monitor/data/analysis.json';
let anCache = null; // { key, obj }

function loadAnalysis() {
  let st = null;
  try { st = fs.statSync(ANALYSIS_FILE); } catch (_) { return null; }
  const key = `${st.mtimeMs}:${st.size}`;
  if (anCache && anCache.key === key) return anCache.obj;
  try {
    const j = JSON.parse(fs.readFileSync(ANALYSIS_FILE, 'utf8'));
    // 结构校验 + 只取聚合面（时序/排行/分布/机构/到期），异常形状整体丢弃
    const ts = j.timeseries || {};
    const ok = Array.isArray(ts.dates) && Array.isArray(ts.totals)
      && ts.dates.length === ts.totals.length
      && (ts.by_slug == null || typeof ts.by_slug === 'object');
    if (!ok) return null;
    const obj = {
      generated_at: j.generated_at, days: j.days, base_local: j.base_local,
      timeseries: {
        dates: ts.dates.map(String).slice(0, 90),
        totals: ts.totals.map(n => (typeof n === 'number' ? n : 0)).slice(0, 90),
        by_slug: ts.by_slug || {},
      },
      zero_rank: Array.isArray(j.zero_rank) ? j.zero_rank.slice(0, 12) : [],
      churn: Array.isArray(j.churn) ? j.churn.slice(0, 12) : [],
      stability: Array.isArray(j.stability) ? j.stability.slice(0, 60) : [],
      proto_global: Array.isArray(j.proto_global) ? j.proto_global.slice(0, 12) : [],
      geo_global: Array.isArray(j.geo_global) ? j.geo_global.slice(0, 12) : [],
      rdap: j.rdap && typeof j.rdap === 'object' ? j.rdap : {},
      expiry: Array.isArray(j.expiry) ? j.expiry.slice(0, 60) : [],
    };
    anCache = { key, obj };
    return obj;
  } catch (_) { return null; }
}

// ---- 机场库数据源：免费候选（sitewatch.json）+ 推荐站档案（sites_digest.json）----
const SITEWATCH_FILE = process.env.AIRMON_SITEWATCH ||
  'E:/Hermes-Agent/Jichang-Monitor/data/sitewatch.json';
const DIGEST_FILE = process.env.AIRMON_SITES_DIGEST ||
  'E:/Hermes-Agent/Jichang-Monitor/data/sites_digest.json';
const SITE_KEYS = ['name', 'url', 'note', 'ok', 'status', 'title', 'tier'];
const DIGEST_KEYS = ['name', 'cat', 'date', 'price', 'free', 'protos', 'dom0', 'related'];

let siteCache = {}; // file -> { key, rows }

function loadSiteRows(file, keys) {
  let st = null;
  try { st = fs.statSync(file); } catch (_) { return []; }
  const key = `${st.mtimeMs}:${st.size}`;
  if (siteCache[file] && siteCache[file].key === key) return siteCache[file].rows;
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    const arr = Array.isArray(j) ? j : (j.results || j.rows || []);
    const rows = arr.map(x => {
      const o = {};
      for (const k of keys) if (x && x[k] !== undefined && x[k] !== null) o[k] = x[k];
      return o;
    });
    siteCache[file] = { key, rows };
    return rows;
  } catch (_) { return []; }
}

// ---- 节点详情（/api/nodes?slug=）----
const localTs = (t) => {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(t || '');
  if (!m) return t || '';
  // 快照 ts 为 UTC；按 UTC+8（机器时区 Asia/Shanghai）转本地展示，与 airmon.dashboard._local 口径一致
  const dt = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + 8 * 3600 * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${dt.getUTCFullYear()}-${p(dt.getUTCMonth() + 1)}-${p(dt.getUTCDate())} ` +
    `${p(dt.getUTCHours())}:${p(dt.getUTCMinutes())}:${p(dt.getUTCSeconds())}`;
};

let nodeCache = { slug: null, key: null, payload: null };
const NODE_CAP = 500;   // 单响应节点上限
const HIST_FILES = 16;  // 走势默认取最近 16 份快照
// 走势窗口：'16'（默认近16轮）| '24h' | '7d' | '30d'（30d 按日合并）
const SPAN_MS = { '24h': 24 * 3600e3, '7d': 7 * 24 * 3600e3, '30d': 30 * 24 * 3600e3 };

function fileTsUtc(f) { // 文件名 YYYYMMDDTHHMMSSZ → epoch ms
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z\.json$/.exec(f);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : 0;
}

export async function getNodes(slug, span) {
  const s = String(slug || '').toLowerCase();
  if (!SLUG_RE.test(s)) return { error: 'bad-slug', slug: s, nodes: [], history: [] };
  const dir = path.join(DATA_DIR, s);
  let files = [];
  try {
    files = fs.readdirSync(dir).filter(f => SNAP_RE.test(f)).sort();
  } catch (_) { /* 目录不存在 */ }
  if (!files.length) {
    return { slug: s, total: 0, shown: 0, nodes: [], history: [], note: 'no-snapshots' };
  }
  const spanKey = SPAN_MS[span] ? span : '16';
  if (spanKey !== '16') {
    const cutoff = Date.now() - SPAN_MS[spanKey];
    files = files.filter(f => { const t = fileTsUtc(f); return t >= cutoff; });
    if (!files.length) {
      return { slug: s, span: spanKey, total: 0, shown: 0, nodes: [], history: [], note: 'empty-window' };
    }
  }
  // 30d：按 UTC 日取每日最后一份快照（文件名有序，Map 天然保留每日最后一项）
  let histFiles;
  if (spanKey === '30d') {
    const byDay = new Map();
    for (const f of files) byDay.set(f.slice(0, 8), f);
    histFiles = [...byDay.values()];
  } else if (spanKey === '16') {
    histFiles = files.slice(-HIST_FILES);
  } else {
    histFiles = files; // 24h/7d 窗口内全部（8~56 份，量可控）
  }
  const key = spanKey + '#' + histFiles.map(f => {
    try {
      const st = fs.statSync(path.join(dir, f));
      return `${f}:${st.mtimeMs}:${st.size}`;
    } catch (_) { return f; }
  }).join('|');
  if (nodeCache.slug === s && nodeCache.key === key) return nodeCache.payload;

  const history = [];
  let latest = null; // 最新非空（与 dashboard「latest」口径一致）
  let best = null;   // 节点数最多
  for (const f of histFiles) {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
      const n = ((j && j.nodes) || []).length;
      const ts_local = localTs(f.replace(/\.json$/, ''));
      history.push({ ts: f.replace(/\.json$/, ''), ts_local, n });
      if (n > 0) latest = { file: f, data: j, ts_local }; // 反复覆盖 = 最新非空
      if (!best || n > best.n) best = { file: f, data: j, n, ts_local };
    } catch (_) { /* 单文件损坏跳过 */ }
  }
  const chosen = latest || best;
  if (!chosen) {
    return { slug: s, span: spanKey, total: 0, shown: 0, nodes: [], history, note: 'all-empty' };
  }
  const all = (chosen.data.nodes || []);
  const nodes = all.slice(0, NODE_CAP).map(nd => {
    const o = {};
    for (const k of NODE_KEYS) {
      const v = nd && nd[k];
      if (typeof v === 'string' || typeof v === 'number') o[k] = v;
    }
    const ips = nd && nd.raw && nd.raw._resolved_ips;
    if (Array.isArray(ips) && typeof ips[0] === 'string') o.r = ips[0].slice(0, 45);
    return o;
  });
  const payload = {
    slug: s,
    span: spanKey,
    file: chosen.file,
    file_local: chosen.ts_local,
    total: all.length,
    shown: nodes.length,
    best_n: best ? best.n : 0,
    nodes,
    history,
    _fetchedAt: new Date().toISOString(),
  };
  nodeCache = { slug: s, key, payload };
  return payload;
}

export async function getDashboard() {
  let raw = null;
  let key = null;
  try {
    const st = fs.statSync(INDEX);
    key = `${st.mtimeMs}:${st.size}`;
    if (cache && cache.key === key) return cache.payload;
    raw = fs.readFileSync(INDEX, 'utf8');
  } catch (_) { /* 源不可读 → 快照 */ }

  let payload = null;
  let src = 'live';
  if (raw) {
    try { payload = sanitize(extractEmbedded(raw)); } catch (_) { payload = null; }
  }
  if (!payload) {
    payload = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
    src = 'snapshot';
  }
  payload._source = src;
  payload._fetchedAt = new Date().toISOString();
  if (src === 'live' && key) cache = { key, payload };
  return payload;
}
