// client.js —— DSH Web GUI 客户端
// factory 必须无副作用：只 require 模块、返回 { inject, apply }。
// 副作用（message 桥监听）在 apply 内经 ctx.effect 注册并返回清理函数，HMR 安全。
window.__ModuleLoader__.load({
  id: '@local/airmon-sidebar',
  factory(require) {
    const React = require('react');
    const NS = 'airmon-sidebar';
    const LABEL = '机场监控';

    // 可选 locale（照 eprint 模式；注册失败不影响功能）
    try {
      const localeMod = require('@deepseek-ai/dsh-client-locale');
      if (localeMod && localeMod.register) {
        localeMod.register(NS, {
          en: { 'panel.title': 'Airport Monitor' },
          'zh-CN': { 'panel.title': LABEL },
        });
      }
    } catch (_) { /* locale 包不可用则用内置中文 */ }

    let frameEl = null;

    function RailIcon() {
      return React.createElement('svg', {
        viewBox: '0 0 24 24', width: 18, height: 18, fill: 'none',
        stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round',
        strokeLinejoin: 'round', 'aria-hidden': true,
      }, React.createElement('path', {
        d: 'M12 3c1.2 0 2 .9 2 2.2V9l6 3.4v1.8l-6-1.6v3.6l2.2 1.8v1.4L12 18.4l-4.2.6v-1.4L10 16.2v-3.6l-6 1.6v-1.8L10 9V5.2C10 3.9 10.8 3 12 3z',
      }));
    }

    function makePanel(/* ctx */) {
      function AirmonPanel() {
        // cache-bust：iframe 每次挂载都强制拿最新 panel.html（no-store 的双保险）
        const src = new URL('/airmon-sidebar/api/panel', document.baseURI).href
          + '?t=' + Date.now();
        return React.createElement('iframe', {
          ref: (el) => { frameEl = el; },
          src,
          title: LABEL,
          sandbox: 'allow-scripts allow-forms allow-modals allow-popups allow-popups-to-escape-sandbox',
          style: {
            flex: 1, width: '100%', height: '100%', border: '0',
            background: 'transparent', display: 'block',
          },
        });
      }
      return AirmonPanel;
    }

    return {
      inject: ['slots', 'layout', 'locale'],
      apply(ctx) {
        // postMessage 数据桥：沙箱 iframe 是 opaque origin，不能直接 fetch，
        // 由 parent（本组件同源）代取 /airmon-sidebar/api/data 再转发（agent-bar 模式）。
        const onMsg = async (e) => {
          const d = e.data;
          if (!d || !frameEl) return;
          if (e.source !== frameEl.contentWindow) return;
          // 节点详情桥：面板弹窗按需取单个机场的节点列表。
          // 优先 /api/nodes（含 16 轮走势）；不可用（旧 handler 未重启）时
          // 回退到 /api/data 里该机场的 node_rows（无走势）。
          if (d.type === 'airmon:getnodes' && d.slug) {
            (async () => {
              const slug = String(d.slug);
              const span = String(d.span || '16');
              let payload = null;
              const base = new URL(document.baseURI);
              try {
                const url = new URL('/airmon-sidebar/api/nodes?slug=' +
                  encodeURIComponent(slug) + '&span=' + encodeURIComponent(span), base).href;
                const r = await fetch(url, { cache: 'no-cache' });
                if (r.ok) payload = await r.json();
              } catch (_) { /* 走回退 */ }
              if (!payload || payload.error) {
                try {
                  const url = new URL('/airmon-sidebar/api/data', base).href;
                  const r = await fetch(url, { cache: 'no-cache' });
                  if (r.ok) {
                    const j = await r.json();
                    const a = (j.airports || []).find(x => x.slug === slug);
                    if (a) {
                      payload = {
                        slug, total: a.node_total != null ? a.node_total : (a.nodes || 0),
                        shown: (a.node_rows || []).length,
                        nodes: a.node_rows || [],
                        history: [],
                        note: 'fallback-data',
                        _fetchedAt: new Date().toISOString(),
                      };
                    }
                  }
                } catch (_) { /* 面板侧显示加载失败 */ }
              }
              try {
                e.source.postMessage({
                  type: 'airmon:nodes', id: d.id, slug, payload,
                }, '*');
              } catch (_) {}
            })();
            return;
          }
          // 检测触发桥：面板「重新获取/刷新全部」→ /api/refresh（栅栏+冷却在 host 侧）
          if (d.type === 'airmon:refresh') {
            (async () => {
              let payload = null;
              try {
                const url = new URL('/airmon-sidebar/api/refresh?slug=' +
                  encodeURIComponent(String(d.slug || '')), document.baseURI).href;
                const r = await fetch(url, { cache: 'no-cache' });
                payload = await r.json().catch(() => ({ error: 'http-' + r.status }));
              } catch (_) { payload = null; }
              try {
                e.source.postMessage({ type: 'airmon:refresh', id: d.id, payload }, '*');
              } catch (_) {}
            })();
            return;
          }
          if (d.type === 'airmon:refreshstatus') {
            (async () => {
              let payload = null;
              try {
                const url = new URL('/airmon-sidebar/api/refresh-status', document.baseURI).href;
                const r = await fetch(url, { cache: 'no-cache' });
                payload = await r.json().catch(() => ({ error: 'http-' + r.status }));
              } catch (_) { payload = null; }
              try {
                e.source.postMessage({ type: 'airmon:refreshstatus', id: d.id, payload }, '*');
              } catch (_) {}
            })();
            return;
          }
          // 机场库一键接入：→ /api/adopt?name=<slug>&panel=<domain>（host 侧校验+冷却）
          if (d.type === 'airmon:adopt' && d.name && d.panel) {
            (async () => {
              let payload = null;
              try {
                const url = new URL('/airmon-sidebar/api/adopt?name=' +
                  encodeURIComponent(String(d.name)) + '&panel=' +
                  encodeURIComponent(String(d.panel)), document.baseURI).href;
                const r = await fetch(url, { cache: 'no-cache' });
                payload = await r.json().catch(() => ({ error: 'http-' + r.status }));
              } catch (_) { payload = { error: 'network' }; }
              try {
                e.source.postMessage({ type: 'airmon:adopt', id: d.id, payload }, '*');
              } catch (_) {}
            })();
            return;
          }
          if (d.type !== 'airmon:get') return;
          let payload = null;
          try {
            const url = new URL('/airmon-sidebar/api/data', document.baseURI).href;
            const r = await fetch(url, { cache: 'no-cache' });
            if (r.ok) payload = await r.json();
          } catch (_) { /* 面板侧会走快照兜底 */ }
          try {
            e.source.postMessage({
              type: 'airmon:data', id: d.id, payload,
              fetchedAt: new Date().toISOString(),
            }, '*');
          } catch (_) {}
        };
        window.addEventListener('message', onMsg);
        ctx.effect(() => () => window.removeEventListener('message', onMsg));

        // 左轨图标（sidebar 把 panellist 的 id 映射到同名 main panel key）
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register(
          { name: 'sidebar.panellist', id: 'airmon', order: 30, label: LABEL },
          RailIcon,
        ));
        // 主列面板
        ctx.slots.inject('main', () => ctx.slots.register(
          { name: 'main', key: 'airmon', locale: NS }, makePanel(ctx)));
      },
    };
  },
});
