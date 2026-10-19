// @local/airmon-sidebar —— Host 壳
// 职责：注册 webServer prefix 路由（panel / data / data.json），套信任栅栏。
// 声明面（本文件/manifest/patch）改动需重启 DSH；logic.js 按 mtime 热更。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const name = '@local/airmon-sidebar';
// webRuntime 服务在本 DSH 构建（app.asar 18302 文件）中零实现——eprint-workbench/agent-bar
// 把它写进必需 inject 导致永久 pending（2026-10-18 实锤）。本插件只用 webServer。
export const inject = ['webServer'];

const PKG_DIR = path.dirname(fileURLToPath(import.meta.url));

export async function apply(ctx) {
  // logic.js 热更：mtime 变化即重 import（eprint-workbench 模式），失败回退旧代
  let cached = null; // { key, mod }
  const logic = async () => {
    const p = path.join(PKG_DIR, 'logic.js');
    const st = fs.statSync(p);
    const key = `${st.mtimeMs}:${st.size}`;
    if (!cached || cached.key !== key) {
      try {
        cached = { key, mod: await import(`./logic.js?v=${Math.round(st.mtimeMs)}`) };
      } catch (e) {
        if (cached) return cached.mod; // 保留旧代
        throw e;
      }
    }
    return cached.mod;
  };

  const sendJson = (res, code, obj) => {
    if (res.writableEnded) return;
    const body = JSON.stringify(obj);
    res.writeHead(code, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    res.end(body);
  };
  const sendFile = (res, file, type) => {
    fs.readFile(file, (err, buf) => {
      if (err) return sendJson(res, 404, { error: 'not-found' });
      res.writeHead(200, { 'content-type': `${type}; charset=utf-8`, 'cache-control': 'no-store' });
      res.end(buf);
    });
  };

  // 信任栅栏：仅 GET；同源浏览器标记；Host 必须是 loopback。
  // eprint-workbench 的 ctx.webRuntime.trustedHosts 局域网放行分支不移植：该服务不存在。
  const fenced = (req) => {
    if (req.method !== 'GET') return false;
    const site = String(req.headers['sec-fetch-site'] || '').toLowerCase();
    if (site && site !== 'same-origin' && site !== 'none') return false;
    const host = String(req.headers.host || '').split(':')[0].toLowerCase();
    if (!host) return false;
    return host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
  };

  // ---- 检测触发（v2）：spawn python -m airmon.panel_refresh，状态读 data/panel_refresh_state.json
  const AIRMON_DIR = 'E:/Hermes-Agent/Jichang-Monitor';
  const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,40}$/;
  const COOLDOWN = { single: 180_000, all: 900_000 };
  let lastStart = { single: 0, all: 0 };
  let inflight = false;
  const adoptAt = {}; // slug → 上次接入时间（冷却 120s）

  const readState = () => {
    try {
      return JSON.parse(fs.readFileSync(path.join(AIRMON_DIR, 'data', 'panel_refresh_state.json'), 'utf8'));
    } catch (_) { return null; }
  };

  const spawnRefresh = (arg, kind) => {
    inflight = true;
    lastStart[kind] = Date.now();
    const child = require_child_process().spawn(
      process.platform === 'win32' ? 'python' : 'python3',
      ['-m', 'airmon.panel_refresh', arg],
      { cwd: AIRMON_DIR, detached: true, stdio: 'ignore', windowsHide: true });
    child.unref();
    child.once('exit', () => { inflight = false; });
    // detached+unref 后 exit 事件仍会触发；再加兜底解锁
    setTimeout(() => { inflight = false; }, 60 * 60 * 1000);
  };
  // index.js 保持零 CommonJS 依赖：动态 import child_process
  let _cp = null;
  const require_child_process = () => _cp; // 在 apply 顶层预先加载
  import('node:child_process').then(m => { _cp = m; });

  const refreshStatus = () => {
    const st = readState() || {};
    return {
      ok: true,
      inflight,
      cooldowns: {
        single_ms: Math.max(0, COOLDOWN.single - (Date.now() - lastStart.single)),
        all_ms: Math.max(0, COOLDOWN.all - (Date.now() - lastStart.all)),
      },
      running: !!st.running,
      pid: st.pid || null,
      progress: st.progress || null,
      started_at: st.started_at || null,
      finished_at: st.finished_at || null,
      jobs: (st.jobs || []).slice(0, 60),
    };
  };

  ctx.webServer.register({
    kind: 'prefix',
    path: '/airmon-sidebar/api',
    handler: async (req, res) => {
      try {
        if (!fenced(req)) return sendJson(res, 403, { error: 'forbidden' });
        const url = new URL(req.url, 'http://local');
        const tail = url.pathname.replace(/\/+$/, '');
        if (tail.endsWith('/data')) {
          const payload = await (await logic()).getDashboard();
          return sendJson(res, 200, payload);
        }
        if (tail.endsWith('/nodes')) {
          // GET /airmon-sidebar/api/nodes?slug=<机场>&span=16|24h|7d|30d
          const slug = url.searchParams.get('slug') || '';
          const span = url.searchParams.get('span') || '16';
          const payload = await (await logic()).getNodes(slug, span);
          return sendJson(res, 200, payload);
        }
        if (tail.endsWith('/refresh-status')) {
          return sendJson(res, 200, refreshStatus());
        }
        if (tail.endsWith('/refresh')) {
          // GET /airmon-sidebar/api/refresh?slug=<slug|all>：触发采集（同 GET 语义+栅栏；
          // 单飞 + 冷却：单机场 3 分钟 / 全量 15 分钟）
          if (!_cp) return sendJson(res, 503, { error: 'booting' });
          if (inflight || (readState() || {}).running) {
            return sendJson(res, 409, { error: 'busy', status: refreshStatus() });
          }
          const slug = url.searchParams.get('slug') || '';
          if (slug === 'all') {
            if (refreshStatus().cooldowns.all_ms > 0) {
              return sendJson(res, 429, { error: 'cooldown', status: refreshStatus() });
            }
            spawnRefresh('--all', 'all');
            return sendJson(res, 200, { ok: true, started: 'all' });
          }
          if (!SLUG_RE.test(slug)) return sendJson(res, 400, { error: 'bad-slug' });
          if (refreshStatus().cooldowns.single_ms > 0) {
            return sendJson(res, 429, { error: 'cooldown', status: refreshStatus() });
          }
          spawnRefresh(slug, 'single');
          return sendJson(res, 200, { ok: true, started: slug });
        }
        if (tail.endsWith('/adopt')) {
          // GET /airmon-sidebar/api/adopt?name=<slug>&panel=<domain>：一键接入新机场
          //（run.py add-airport --name <slug> --panel https://<domain> --domains <domain>，
          //  fire-and-forget；结果落 airports.yaml，下一轮采集/刷新即生效）
          if (!_cp) return sendJson(res, 503, { error: 'booting' });
          const name = (url.searchParams.get('name') || '').toLowerCase().trim();
          const panel = (url.searchParams.get('panel') || '').trim();
          if (!SLUG_RE.test(name)) return sendJson(res, 400, { error: 'bad-name' });
          if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(panel)) return sendJson(res, 400, { error: 'bad-panel' });
          const now = Date.now();
          if ((adoptAt[name] || 0) > now - 120_000) {
            return sendJson(res, 429, { error: 'cooldown' });
          }
          adoptAt[name] = now;
          const child = _cp.spawn(
            process.platform === 'win32' ? 'python' : 'python3',
            ['run.py', 'add-airport', '--name', name,
             '--panel', `https://${panel}`, '--domains', panel],
            { cwd: AIRMON_DIR, detached: true, stdio: 'ignore', windowsHide: true });
          child.unref();
          return sendJson(res, 200, { ok: true, started: name, panel });
        }
        if (tail.endsWith('/panel')) {
          return sendFile(res, path.join(PKG_DIR, 'panel.html'), 'text/html');
        }
        if (tail.endsWith('/data.json')) {
          return sendFile(res, path.join(PKG_DIR, 'data.json'), 'application/json');
        }
        return sendJson(res, 404, { error: 'not-found' });
      } catch (e) {
        return sendJson(res, 500, { error: 'internal' }); // 不回显内部细节
      }
    },
  });
}
