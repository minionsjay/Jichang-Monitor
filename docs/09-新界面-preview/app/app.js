/* 机场监控台 · 作战室（A 方向）
 * 渲染 + 视图切换 + 抽屉 + 三处基本动效
 * 数据来自 data.js（window.AIRMON，由 tools/gen_panel_data.py 生成）
 */
(function () {
  "use strict";

  var D = window.AIRMON;
  if (!D) { document.body.innerHTML = "<p style='padding:40px;color:#f0555c'>data.js 未加载</p>"; return; }

  /* ------------------------------------------------------------ 工具 */
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    });
  }
  function num(n) {
    if (n == null || isNaN(n)) return "—";
    return Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }
  function pct(a, b) { return b ? Math.round((a / b) * 1000) / 10 : 0; }
  function signed(n) { return n > 0 ? "+" + num(n) : num(n); }
  function bytesMB(b) {
    if (b == null) return "—";
    return (b / 1048576).toFixed(0) + " MB";
  }
  function relTime(iso) {
    if (!iso) return "—";
    var t = Date.parse(iso);
    if (isNaN(t)) return String(iso).slice(0, 16).replace("T", " ");
    var dh = (Date.now() - t) / 3600000;
    if (dh < 1) return Math.max(1, Math.round(dh * 60)) + " 分钟前";
    if (dh < 48) return dh.toFixed(1).replace(".0", "") + " 小时前";
    return Math.round(dh / 24) + " 天前";
  }
  function shortTime(iso) {
    if (!iso) return "—";
    var t = Date.parse(iso);
    if (isNaN(t)) return String(iso).slice(0, 16).replace("T", " ");
    var d = new Date(t);
    var p = function (x) { return (x < 10 ? "0" : "") + x; };
    return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  var STATE_CLS = { A: "ok", B: "b", C: "c", D: "d" };
  var STATE_NAME = { A: "可用", B: "异常", C: "仅客户端", D: "断流" };
  function stCls(s) { return STATE_CLS[s] || ""; }
  function stName(s) { return STATE_NAME[s] || s || "—"; }

  var PROTO_COLOR = {
    anytls: "#3ee0b0", vless: "#5c8bff", ss: "#f2b33d", hysteria2: "#9b8cff",
    trojan: "#35d08a", vmess: "#f0763d", unknown: "#4a5261", mieru: "#6b7280",
    vmux: "#7c8798", hysteria: "#c084fc", ninja: "#f472b6", aero_v2: "#22d3ee"
  };
  function protoColor(p) { return PROTO_COLOR[p] || "#4a5261"; }
  var GEO_COLOR = ["#3ee0b0", "#5c8bff", "#f2b33d", "#9b8cff", "#35d08a", "#f0763d", "#22d3ee", "#f472b6", "#c084fc", "#94a3b8"];

  function daysText(d) {
    if (d == null) return "—";
    if (d < 0) return "已过期 " + (-d) + " 天";
    return d + " 天";
  }
  function daysCls(d) {
    if (d == null) return "dim";
    if (d < 0) return "pill d";
    if (d <= 7) return "pill d";
    if (d <= 30) return "pill b";
    return "pill t";
  }
  function pill(cls, txt) { return '<span class="' + cls + '">' + txt + "</span>"; }
  function dot(cls) { return '<i class="dot ' + cls + '"></i>'; }

  /* ------------------------------------------------------------ 状态 */
  var S = { view: "ov", q: "", al: "all", lib: "all", siteQ: "", siteMon: false, kn: "all", nd: null, ndProto: "all", density: "m", group: "", drawn: {} };
  /* 默认就用「状态 + 通道」两级聚合：绿的一坨、里面再按通道分簇 */
  S.group = "channel";
  try {
    var _g0 = localStorage.getItem("airmon.group");
    if (_g0 === "") S.group = "";
  } catch (e) {}

  var T = D.totals || {};
  var APTS = D.airports || [];
  var bySlug = {};
  APTS.forEach(function (a) { bySlug[a.slug] = a; });
  /* 机场显示名：优先中文名，英文 slug 作副标题 */
  function nmOf(a) { return (a && (a.name_cn || a.slug)) || "—"; }
  function nmBySlug(slug) { var a = bySlug[slug]; return nmOf(a || { slug: slug }); }
  /* 中文名才需要英文副名；纯 ASCII 品牌名（BYWAVE/DOVE/Mitce…）不重复显示 */
  function enSuffix(a) { return (a && a.name_cn && /[^\x00-\x7F]/.test(a.name_cn) && a.slug.length <= 10) ? '<i class="en">' + esc(a.slug) + "</i>" : ""; }
  function enSuffix2(a) { return (a && a.name_cn && /[^\x00-\x7F]/.test(a.name_cn) && a.slug.length <= 14) ? '<i class="en2">' + esc(a.slug) + "</i>" : ""; }

  var ORDER = { D: 0, B: 1, C: 2, A: 3 };
  var SORTED = APTS.slice().sort(function (x, y) {
    var o = (ORDER[x.state] == null ? 9 : ORDER[x.state]) - (ORDER[y.state] == null ? 9 : ORDER[y.state]);
    return o !== 0 ? o : (y.nodes - x.nodes);
  });

  /* ------------------------------------------------------------ 数字滚动（首次入场） */
  var counted = {};
  function countUp(node, target, dur) {
    if (!node) return;
    var start = performance.now();
    var d = dur || 620;
    var from = 0;
    function frame(t) {
      var p = Math.min(1, (t - start) / d);
      var e = 1 - Math.pow(1 - p, 3);
      node.textContent = num(Math.round(from + (target - from) * e));
      if (p < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }
  function countOnce(key, node, target) {
    if (counted[key]) { node.textContent = num(target); return; }
    counted[key] = 1;
    countUp(node, target);
  }

  /* ------------------------------------------------------------ 总览 */
  /* 获取通道分组：把不能用订阅链接拿的机场归到一起 */
  var CHANNELS = [
    { k: "订阅直连", d: "订阅链接直接拉取，可导出配置" },
    { k: "订阅失效", d: "订阅链接失效（403/404/过期），节点是历史或走别的入口" },
    { k: "本地抓包", d: "客户端把配置交给内核时截下来（hhy / 青云梯）" },
    { k: "本地解包", d: "解本地加密配置（DOVE）" },
    { k: "客户端内存", d: "读客户端进程内存，需要管理员" },
    { k: "仅客户端待打通", d: "只能用客户端，目前还没打通" },
    { k: "已停用", d: "套餐过期或主动下线，不再采集" },
    { k: "无数据", d: "没有任何可用快照" }
  ];
  var ST_ORDER = { A: 0, B: 1, C: 2, D: 3 };

  function cellHtml(a) {
      var h = "";
      var cls = stCls(a.state);
      var clOnly = a.type === "client" && !a.has_sub;
      var expired = a.days != null && a.days < 0;
      /* 订阅「限时开关」被机场关掉：不是故障，是面板上的开关到点自动关。
         拉取会拿到 403，重试无用；节点还是上一轮的，所以状态不动，只加个提示标。 */
      var subc = a.sub_closed && a.sub_closed.at;
      /* 限时开关型机场：凭据里配了面板令牌时，run.py 拉取遇到 403 会自动调面板
         openSubscribe 再重拉，不用人管；令牌过期才需要人去面板重新复制。 */
      var autoOk = a.sub_auto && a.sub_auto.ok;
      var tip = a.slug + " · " + stName(a.state) + " · 节点 " + num(a.nodes) + " 个（有协议）" +
        (a.frag ? "\n另有 " + num(a.frag) + " 条无协议残片（内存扫描只拿到域名+端口，导不进配置）" : "") +
        (clOnly ? "\n只能用客户端获取（没有可用的订阅地址）" : "") +
        (expired ? "\n套餐" + (a.expire || "") + " 已到期（" + Math.abs(a.days) + " 天前）" : "") +
        (a.reason ? "\n" + a.reason : "");
      var exTxt = a.exported ? "可导出 " + num(a.exported) : (expired ? "套餐过期" : "无可导出");
      h += '<button class="cell ' + cls + (expired ? " exp" : "") + '" data-slug="' + esc(a.slug) + '" title="' + esc(tip) + '">' +
        (clOnly ? '<i class="cl" aria-label="只能用客户端获取">客</i>' : "") +
        '<span class="nm">' + esc(nmOf(a)) + enSuffix(a) + "</span>" +
        '<span class="ct">' + (a.nodes ? num(a.nodes) : "0") + "</span>" +
        '<span class="ft">' +
          '<span class="st"><span class="stw">' + esc(stName(a.state)) + "</span>" +
            (expired ? '<i class="xd" aria-label="套餐已到期">到期</i>' : "") +
            (subc ? '<i class="xd subc" title="订阅开关被机场关闭（' + esc(a.sub_closed.at) + '）——' +
              (autoOk ? "面板令牌还有效（剩 " + num(a.sub_auto.hours) + " 小时），下次拉取会自动开启"
                      : "面板令牌已过期或未配置，需去面板开启后重新复制面板令牌") +
              '">' + (autoOk ? "待自动开启" : "订阅关闭") + "</i>" : "") + "</span>" +
          '<span class="ex' + (a.exported ? "" : (expired ? " bad" : " dim")) + '">' + exTxt + "</span>" +
        "</span>" +
        "</button>";
    return h;
  }

  /* 一级=状态（绿/黄/蓝/红），二级=获取通道。
     先让同状态的聚在一起（用户一眼看「绿的都在这」），组内再按通道分簇。 */
  var ST_CAPS = [
    ["A", "可用", "ok"],
    ["B", "异常", "b"],
    ["C", "仅客户端", "c"],
    ["D", "断流", "d"]
  ];

  function buildStateChannelGroups() {
    var out = "";
    ST_CAPS.forEach(function (st) {
      var byState = SORTED.filter(function (a) { return a.state === st[0]; });
      if (!byState.length) return;
      out += '<div class="mxgroup stg"><div class="mxg-h">' +
        '<span class="dot ' + st[2] + '"></span><b>' + esc(st[1]) + "</b>" +
        '<span class="n">' + num(byState.length) + " 家</span>" +
        '<span class="mxg-d">' + esc(st[0] === "A" ? "订阅/抓包/解包/内存任一路拿到节点，可导出配置"
          : st[0] === "B" ? "入口还在但采集卡住，或只有碎片节点"
          : st[0] === "C" ? "订阅不通、必须走客户端"
          : "无新节点落地或被停用") + "</span></div>";

      CHANNELS.forEach(function (c) {
        var list = byState.filter(function (a) { return (a.channel || "无数据") === c.k; });
        if (!list.length) return;
        list.sort(function (x, y) { return (y.nodes || 0) - (x.nodes || 0); });
        out += '<div class="mxg-sub"><b>' + esc(c.k) + "</b><span>" + num(list.length) + " 家</span>" +
          '<span class="mxg-d">' + esc(c.d) + "</span></div>" +
          '<div class="matrix" data-d="' + S.density + '">' + list.map(cellHtml).join("") + "</div>";
      });
      out += "</div>";
    });
    return out || '<div class="empty">没有机场</div>';
  }

  function renderOverview(force) {
    var v = $("#v-ov");
    if (S.drawn.ov && !force) { v.style.display = "block"; return; }
    S.drawn.ov = 1;

    var kpis = [
      { lb: "监控机场", vl: T.airports, ft: "47 个 data 目录", cls: "" },
      { lb: "本轮可用", vl: T.ok, ft: "订阅通达", cls: "ok" },
      { lb: "异常", vl: T.b, ft: "订阅失效或采集卡住", cls: "b" },
      { lb: "仅客户端", vl: T.c, ft: "订阅不通、客户端可用", cls: "c" },
      { lb: "断流", vl: T.d, ft: "无新节点落地", cls: "d" },
      { lb: "可用节点", vl: T.nodes, ft: "可导出 " + num(T.exported) + (T.frag ? " · 碎片 " + num(T.frag) : ""), cls: "t" }
    ];

    var h = '<div class="kpis">';
    kpis.forEach(function (k, i) {
      h += '<div class="kpi ' + k.cls + '">' +
        '<div class="lb">' + esc(k.lb) + "</div>" +
        '<div class="vl" data-cnt="' + i + '">0</div>' +
        '<div class="ft">' + esc(k.ft) + "</div></div>";
    });
    h += "</div>";

    /* 矩阵 */
    h += '<div class="sec"><div class="sec-h"><h2>机场矩阵</h2>' +
      '<span class="n">' + num(APTS.length) + " 家 · " + (S.group === "channel" ? "按状态 → 获取通道 两级聚合" : "按状态排序") + "</span>" +
      '<span class="sp"></span>' +
      '<div class="row small dim" style="gap:12px">' +
      '<span class="row" style="gap:5px">' + dot("ok") + "可用 " + T.ok + "</span>" +
      '<span class="row" style="gap:5px">' + dot("b") + "异常 " + T.b + "</span>" +
      '<span class="row" style="gap:5px">' + dot("c") + "仅客户端 " + T.c + "</span>" +
      '<span class="row" style="gap:5px">' + dot("d") + "断流 " + T.d + "</span>" +
      '<span class="row" style="gap:5px"><i class="cl inline">客</i>只能用客户端获取</span>' +
      "</div>" +
      '<div class="dseg dseg-g" role="group" aria-label="分组方式">' +
      [["", "按状态"], ["channel", "状态 + 通道"]].map(function (kv) {
        return '<button class="dseg-b' + ((S.group || "") === kv[0] ? " on" : "") + '" data-g="' + kv[0] + '">' + kv[1] + "</button>";
      }).join("") +
      "</div>" +
      '<div class="dseg" role="group" aria-label="卡片尺寸">' +
      ["s", "m", "l"].map(function (k) {
        var lbl = { s: "小", m: "中", l: "大" }[k];
        return '<button class="dseg-b' + (S.density === k ? " on" : "") + '" data-d="' + k + '">' + lbl + "</button>";
      }).join("") +
      "</div></div>";
    h += '<div class="sec-b">';
    if (S.group === "channel") {
      h += buildStateChannelGroups();
    } else {
      h += '<div class="matrix" id="mx" data-d="' + S.density + '">' + SORTED.map(cellHtml).join("") + "</div>";
    }
    h += "</div></div>";

    /* 构成 */
    h += '<div class="grid2 mt14">' + barBlock("协议构成", D.protos || [], protoColor, "节点") +
      barBlock("地区分布", D.geos || [], null, "节点") + "</div>";

    v.innerHTML = h;
    $$(".matrix .cell", v).forEach(function (c) {
      c.addEventListener("click", function () { openDrawer(c.getAttribute("data-slug")); });
    });
    $$(".dseg-b", v).forEach(function (b) {
      b.addEventListener("click", function () { S.density = b.getAttribute("data-d"); renderOverview(true); });
    });
    $$(".dseg-g .dseg-b", v).forEach(function (b) {
      b.addEventListener("click", function () {
        S.group = b.getAttribute("data-g");
        try { localStorage.setItem("airmon.group", S.group || ""); } catch (e) {}
        renderOverview(true);
      });
    });
    countOnce("ov-airports", $('[data-cnt="0"]', v), T.airports);
    countOnce("ov-ok", $('[data-cnt="1"]', v), T.ok);
    countOnce("ov-b", $('[data-cnt="2"]', v), T.b);
    countOnce("ov-c", $('[data-cnt="3"]', v), T.c);
    countOnce("ov-d", $('[data-cnt="4"]', v), T.d);
    countOnce("ov-nodes", $('[data-cnt="5"]', v), T.nodes);
  }

  function barBlock(title, pairs, colorFn, unit) {
    var arr = pairs.filter(function (p) { return Array.isArray(p) && p[1] > 0; });
    var total = arr.reduce(function (s, p) { return s + p[1]; }, 0) || 1;
    var top = arr.slice(0, 8);
    var rest = arr.slice(8).reduce(function (s, p) { return s + p[1]; }, 0);
    if (rest > 0) top.push(["其他", rest]);

    var h = '<div class="sec"><div class="sec-h"><h2>' + esc(title) + "</h2>" +
      '<span class="n">' + num(total) + " " + esc(unit) + "</span></div>" +
      '<div class="sec-b"><div class="bars">';

    var stack = '<div class="stack">';
    top.forEach(function (p, i) {
      var c = colorFn ? colorFn(p[0]) : GEO_COLOR[i % GEO_COLOR.length];
      stack += '<i style="width:' + pct(p[1], total) + "%;background:" + c + '" title="' + esc(p[0]) + " " + num(p[1]) + '"></i>';
    });
    stack += "</div>";

    h += '<div class="bar-row"><div class="cap"><b>合计</b><span class="n">' + num(total) + "</span></div>" + stack +

      '<div class="legend">';
    top.forEach(function (p, i) {
      var c = colorFn ? colorFn(p[0]) : GEO_COLOR[i % GEO_COLOR.length];
      h += "<span><i style=\"background:" + c + '"></i>' + esc(p[0]) + " <em>" + num(p[1]) + "</em></span>";
    });
    h += "</div></div></div></div></div>";
    return h;
  }

  /* ------------------------------------------------------------ 到期 */
  function renderExpiry() {
    var v = $("#v-exp");
    var rows = APTS.filter(function (a) { return a.days != null || a.unlimited; })
      .sort(function (x, y) {
        var dx = x.days == null ? 99999 : x.days;
        var dy = y.days == null ? 99999 : y.days;
        return dx - dy;
      });

    var buckets = {
      expired: APTS.filter(function (a) { return a.days != null && a.days < 0; }).length,
      d7: APTS.filter(function (a) { return a.days != null && a.days >= 0 && a.days <= 7; }).length,
      d30: APTS.filter(function (a) { return a.days != null && a.days > 7 && a.days <= 30; }).length,
      d90: APTS.filter(function (a) { return a.days != null && a.days > 30 && a.days <= 90; }).length,
      unlim: APTS.filter(function (a) { return a.unlimited; }).length,
      nodata: APTS.filter(function (a) { return a.days == null && !a.unlimited; }).length
    };

    var h = '<div class="sec"><div class="sec-h"><h2>套餐与流量</h2>' +
      '<span class="n">' + num(rows.length) + " 家有数据 · " + num(APTS.length) + " 家</span><span class=\"sp\"></span>" +
      '<div class="chips">' +
      '<span class="chip on">已过期 <span class="n">' + buckets.expired + "</span></span>" +
      '<span class="chip">30 天内 <span class="n">' + (buckets.d7 + buckets.d30) + "</span></span>" +
      '<span class="chip">不限量 <span class="n">' + buckets.unlim + "</span></span>" +
      '<span class="chip">无数据 <span class="n">' + buckets.nodata + "</span></span>" +
      "</div></div>";

    h += '<div class="sec-b tight"><div class="tbl-wrap"><table class="tbl"><thead><tr>' +
      "<th>机场</th><th>状态</th><th>到期日</th><th class=\"num\">剩余</th>" +
      "<th>流量</th><th class=\"num\">已用</th><th>来源</th></tr></thead><tbody>";

    rows.forEach(function (a) {
      var used = (a.total_gb != null && a.used_pct != null) ? (a.total_gb * a.used_pct / 100) : null;
      var barCls = a.used_pct >= 90 ? "bad" : (a.used_pct >= 75 ? "warn" : "");
      var traffic;
      if (a.unlimited) {
        traffic = '<span class="pill t">不限量</span>';
      } else if (a.total_gb != null) {
        traffic = '<div class="row" style="gap:8px"><div class="mini-bar ' + barCls + '" style="width:110px"><i style="width:' +
          Math.min(100, a.used_pct || 0) + '%"></i></div><span class="mono small dim">' + (a.used_pct || 0) + "%</span></div>";
      } else {
        traffic = '<span class="dim">—</span>';
      }
      h += "<tr>" +
        '<td class="nm">' + esc(nmOf(a)) + enSuffix2(a) + "</td>" +
        '<td><span class="row" style="gap:6px">' + dot(stCls(a.state)) + '<span class="dim xsmall">' + esc(stName(a.state)) + "</span></span></td>" +
        '<td class="mono">' + esc(a.expire || "—") + "</td>" +
        '<td class="num"><span class="' + daysCls(a.days) + '">' + esc(daysText(a.days)) + "</span></td>" +
        "<td>" + traffic + "</td>" +
        '<td class="num mono">' + (used != null ? num(Math.round(used)) + " / " + num(a.total_gb) + " GB" : "—") + "</td>" +
        '<td class="xsmall dim">' + esc(a.days != null ? "订阅响应头" : "—") + "</td></tr>";
    });
    h += "</tbody></table></div></div></div>";

    h += '<div class="sec mt14"><div class="sec-h"><h2>到期时间线</h2><span class="n">按剩余天数</span></div><div class="sec-b">' +
      '<div class="row wrap" style="gap:6px">';
    rows.forEach(function (a) {
      if (a.days == null) return;
      var cls = a.days < 0 ? "pill d" : (a.days <= 30 ? "pill b" : "pill");
      h += '<span class="' + cls + '" title="' + esc(a.slug) + '">' + esc(nmOf(a)) + " " + (a.days < 0 ? "过期" + (-a.days) + "天" : a.days + "天") + "</span>";
    });
    h += "</div></div></div>";

    v.innerHTML = h;
  }

  /* ------------------------------------------------------------ 告警 */
  /* 2026-10-25 之前产生的告警，是旧引擎（detect.py 重写前）的判定：
     domain 维度不做域名合法性校验，IP 命中不剔除大厂域前置与内存碎片节点。
     给它们打灰标，避免被当成现口径的结论。 */
  var OLD_ENGINE_TS = "2026-10-25T00:00:00Z";

  function renderAlerts() {
    var v = $("#v-al");
    var q = S.q.toLowerCase();
    var all = D.alerts || [];
    var kinds = D.alertKinds || {};
    var list = all.filter(function (x) {
      if (S.al !== "all" && x.kind !== S.al) return false;
      if (!q) return true;
      return (x.slug + " " + x.lines.join(" ")).toLowerCase().indexOf(q) >= 0;
    });

    var KIND_NAME = { stale: "陈旧", churn: "波动", hw: "华为", other: "其他" };
    var KIND_CLS = { stale: "b", churn: "c", hw: "d", other: "" };

    var h = '<div class="sec"><div class="sec-h"><h2>告警流</h2>' +
      '<span class="n">' + num(list.length) + " / " + num(all.length) + " 块</span><span class=\"sp\"></span>" +
      '<div class="chips" id="alChips">' +
      '<button class="chip' + (S.al === "all" ? " on" : "") + '" data-al="all">全部 <span class="n">' + all.length + "</span></button>";
    ["stale", "churn", "hw", "other"].forEach(function (k) {
      h += '<button class="chip' + (S.al === k ? " on" : "") + '" data-al="' + k + '">' + KIND_NAME[k] +
        ' <span class="n">' + (kinds[k] || 0) + "</span></button>";
    });
    h += "</div></div>";

    h += '<div class="sec-b tight"><div class="tbl-wrap" style="max-height:calc(100vh - 290px);overflow-y:auto"><table class="tbl compact"><tbody>';
    if (!list.length) {
      h += '<tr><td class="dim">没有匹配的告警。平均水平线上，这是好消息。</td></tr>';
    }
    list.forEach(function (x) {
      h += '<tr><td style="width:120px" class="mono xsmall dim nowrap">' + esc(shortTime(x.ts)) + "</td>" +
        '<td style="width:130px" class="nm" title="' + esc(x.slug) + '">' + esc(nmBySlug(x.slug)) + "</td>" +
        '<td style="width:112px">' + pill("pill " + (KIND_CLS[x.kind] || ""), KIND_NAME[x.kind] || x.kind) +
          (x.kind === "hw" && String(x.ts) < OLD_ENGINE_TS
            ? ' <span class="tag old" title="2026-10-25 之前旧引擎判定：domain 维度未校验域名合法性，IP 命中未剔除大厂域前置与内存碎片节点">旧口径</span>'
            : "") + "</td>" +
        '<td class="xsmall">' + esc(x.lines.join(" · ").slice(0, 180)) + "</td></tr>";
    });
    h += "</tbody></table></div></div></div>";

    h += '<div class="mt14 hint">陈旧 = 快照超过 6 小时未更新；波动 = 本轮相对上一份快照的大幅增删；华为 = 命中云厂商特征；带<b>旧口径</b>灰标的是 2026-10-25 引擎重写之前的记录（当时 domain 维度不校验域名合法性、IP 命中不剔除大厂域前置与碎片节点），不代表现在仍命中。空块已在生成阶段丢弃。</div>';
    v.innerHTML = h;

    $$("#alChips .chip", v).forEach(function (b) {
      b.addEventListener("click", function () {
        S.al = b.getAttribute("data-al");
        renderAlerts();
      });
    });
  }

  /* ------------------------------------------------------------ 华为云 */
  function renderHuawei() {
    var v = $("#v-hw");
    var L = D.hwLedger || null;
    if (!L) {
      v.innerHTML = '<div class="sec"><div class="sec-b"><div class="hint">还没有台账。执行 ' +
        '<span class="mono">python -X utf8 tools/huawei_ledger.py</span> 生成 data/huawei_ledger.json 后刷新。</div></div></div>';
      return;
    }
    var byType = (L.current || {}).by_type || {};
    var hist = L.history || {};
    var byDim = hist.by_dimension || {};
    var byAp = hist.by_airport || {};
    var domRev = hist.domain_review || {};
    var sc = L.scanned || {};
    var hitNow = (byType.A || 0) + (byType.B || 0) + (byType.C || 0);
    var histTotal = (byDim.rdap_name || 0) + (byDim.asn || 0) + (byDim.domain || 0) + (byDim.cidr || 0);
    var apN = Object.keys(byAp).length;

    var derived = hist.fronting_derived_hits || {};
    var derivedN = 0;
    Object.keys(derived).forEach(function (k) { derivedN += derived[k]; });
    var cards = [
      { lb: "当前命中", vl: hitNow, ft: "本轮 " + num(sc.airports || 0) + " 家 / " + num(sc.nodes || 0) + " 节点" },
      { lb: "历史命中（干净）", vl: histTotal, ft: "近 " + num(sc.history_days || 30) + " 天 · 已剔除假命中" },
      { lb: "已剔除的假命中", vl: derivedN + (domRev.total || 0), ft: "前置/碎片带出 " + num(derivedN) + " + domain 误报 " + num(domRev.total || 0) },
      { lb: "大厂域前置", vl: hist.fronting_hits || 0, ft: "单列，不算「机场在华为云」" }
    ];
    var h = '<div class="hw-cards">';
    cards.forEach(function (c, i) {
      h += '<div class="hw-c"><div class="lb">' + esc(c.lb) + '</div><div class="vl" data-hw="' + i + '">0</div><div class="ft">' + esc(c.ft) + "</div></div>";
    });
    h += "</div>";

    /* 用当前引擎重扫的结果 */
    h += '<div class="sec mt14"><div class="sec-h"><h2>本轮重扫结果</h2>' +
      '<span class="n">' + esc(L.engine || "") + "</span></div><div class=\"sec-b\">" +
      '<div class="grid2"><div><dl class="kv">' +
      "<dt>A 真在华为云</dt><dd>" + num(byType.A || 0) + " 条</dd>" +
      "<dt>B 经华为 CDN</dt><dd>" + num(byType.B || 0) + " 条</dd>" +
      "<dt>C 大厂域前置</dt><dd>" + num(byType.C || 0) + " 条</dd>" +
      "<dt>D 无佐证</dt><dd>" + num(byType.D || 0) + " 条</dd>" +
      "</dl></div><div class=\"small fg2\" style=\"line-height:1.9\">" +
      (hitNow === 0
        ? "<b>本轮 0 命中</b>：47 家的节点 IP 没有一家落在华为云段，也没有域名 CNAME 到华为 CDN、没有借大厂域前置。"
        : "<b>本轮 " + num(hitNow) + " 条命中</b>：明细见下表。") +
      '<div class="mt8 hint">判定用快照里已存的解析结果（_resolved_ips / _cnames / _rdap），不重新联网，所以结果是确定的，不是抽样。</div>' +
      "</div></div></div></div>";

    /* 四类语义 */
    var types = L.types || {};
    h += '<div class="sec mt14"><div class="sec-h"><h2>四类分别是什么</h2><span class="n">别把四件事混成一个数</span></div>' +
      '<div class="sec-b"><div class="small fg2" style="line-height:2">';
    [["A", "真在华为云"], ["B", "经华为 CDN"], ["C", "大厂域前置"], ["D", "无佐证"]].forEach(function (t) {
      h += "<div><b class=\"mono\">" + t[0] + "</b> " + esc(t[1]) + "：" + esc(types[t[0]] || "") + "</div>";
    });
    h += "</div><div class=\"mt8 hint\">C 类（大厂域前置）单列：节点连接目标本身就是 chat.deepseek.com / www.apple.com 这类大厂域名，解析出的 IP 是大厂自己的服务器，与机场无关。协议不明、raw 里没有完整配置的节点（内存碎片把解析 IP 当成 server）也不计入。</div></div></div>";

    /* 当前命中明细 */
    var cur = (L.current || {}).findings || [];
    h += '<div class="sec mt14"><div class="sec-h"><h2>本轮命中明细</h2><span class="n">' + num(cur.length) + " 条</span></div>" +
      '<div class="sec-b tight"><div class="tbl-wrap"><table class="tbl compact"><thead><tr>' +
      "<th>机场</th><th>类型</th><th>维度</th><th>命中</th><th>证据</th><th>位置</th><th>置信</th>" +
      "</tr></thead><tbody>";
    if (!cur.length) {
      h += '<tr><td colspan="7" class="dim">本轮 0 命中，历史上（近 ' + num(sc.history_days || 30) + ' 天）剔除假命中后也是 0 条。' +
        '同一个引擎在更早的 400 天窗口里扫出过 276 条 rdap 命中，说明它确实有检出能力——现在没有，是真的没有。</td></tr>';
    }
    cur.slice(0, 60).forEach(function (f) {
      h += "<tr>" +
        '<td class="nm">' + esc(f.airport) + "</td>" +
        "<td>" + pill(f.type === "A" ? "pill d" : (f.type === "B" ? "pill b" : "pill t"), esc(f.type || "—")) + "</td>" +
        '<td class="mono xsmall">' + esc(f.dimension || "—") + "</td>" +
        '<td class="xsmall">' + esc(f.rule || "—") + "</td>" +
        '<td class="xsmall mono">' + esc(f.evidence || "—") + "</td>" +
        '<td class="xsmall dim">' + esc(f.context || "—") + "</td>" +
        '<td class="xsmall">' + esc(f.confidence || "—") + "</td></tr>";
    });
    h += "</tbody></table></div></div></div>";

    /* 历史台账 */
    var apList = Object.keys(byAp).map(function (k) { return [k, byAp[k]]; })
      .sort(function (a, b) { return b[1].total - a[1].total; });
    h += '<div class="sec mt14"><div class="sec-h"><h2>历史台账</h2>' +
      '<span class="n">' + num(histTotal) + " 条 / " + num(apN) + " 家</span></div>" +
      '<div class="sec-b tight"><div class="tbl-wrap"><table class="tbl compact"><thead><tr>' +
      "<th>机场</th><th class=\"num\">合计</th><th class=\"num\">rdap</th><th class=\"num\">asn</th><th class=\"num\">domain</th>" +
      "<th>首次</th><th>末次</th><th>结论</th></tr></thead><tbody>";
    if (!apList.length) {
      h += '<tr><td colspan="8" class="dim">近 ' + num(sc.history_days || 30) + ' 天没有任何一家机场的节点落在华为云。' +
        '扫了 ' + num(sc.history_snapshots || 0) + ' 份历史快照，剔除了 ' + num(derivedN) + ' 条前置/碎片带出的假命中。</td></tr>';
    }
    apList.forEach(function (r) {
      var slug = r[0], a = r[1];
      var verdict = a.rdap_name + a.asn > 0
        ? (a.last >= "2026-10-20" ? "近期仍有" : "已迁出华为云")
        : "仅 domain 命中（已判误报）";
      h += "<tr>" +
        '<td class="nm">' + esc(slug) + "</td>" +
        '<td class="num">' + num(a.total) + "</td>" +
        '<td class="num">' + num(a.rdap_name) + "</td>" +
        '<td class="num">' + num(a.asn) + "</td>" +
        '<td class="num">' + num(a.domain) + "</td>" +
        '<td class="xsmall">' + esc(a.first || "—") + "</td>" +
        '<td class="xsmall">' + esc(a.last || "—") + "</td>" +
        '<td class="xsmall dim">' + esc(verdict) + "</td></tr>";
    });
    h += "</tbody></table></div></div></div>";

    /* domain 复核 + 旧数据作废 */
    h += '<div class="grid2 mt14">' +
      '<div class="sec"><div class="sec-h"><h2>domain 维度复核</h2><span class="n">误报根因</span></div><div class="sec-b">' +
      '<div class="small fg2" style="line-height:1.9">' +
      "<div>历史 domain 命中 <b>" + num(domRev.total || 0) + "</b> 条，其中 <b>" + num(domRev.glued_or_invalid || 0) + "</b> 条的证据根本不是合法域名。</div>" +
      '<div class="mt8 hint">' + esc(domRev.verdict || "") + "</div>" +
      '<div class="mt8 mono xsmall" style="line-height:1.7;word-break:break-all">' +
      "cdnhwcljk104.comcdnhwclxu105.comcdnhwcbqs106.comdoh.pub" +
      "<br>↑ 客户端内存里四个域名连写、分隔符丢失，按子串匹配就命中了 cdnhwc" +
      "</div></div></div></div>" +
      '<div class="sec"><div class="sec-h"><h2>旧流量式检测已撤下</h2><span class="n">那行数据是假的</span></div><div class="sec-b">' +
      '<div class="small fg2" style="line-height:1.9">' +
      "<div>之前这里显示过一条 <span class=\"mono\">152.69.227.30 · strong · applegame</span>，来源是 <span class=\"mono\">data/huawei_findings.json</span>。</div>" +
      "<div class=\"mt8\">查证：该 IP 的 RDAP 是 <b>ORACLE-MY / Oracle Corporation</b>、AS31898 韩国春川，<b>不是华为</b>；而且那份文件的 format 是 <span class=\"mono\">generic-csv</span>，是当年按样例格式造的输入，不是真实 VPC 流日志。所以整个「会话特征 + 评分」面板都撤了，换成左边这套基于快照 IP/CNAME 的可复核台账。</div>" +
      '<div class="mt8 hint">要恢复流量式检测，得先有真实的 VPC 流日志（华为云 LTS/VPC 流日志导出），否则算出来的分数没有意义。</div>' +
      "</div></div></div></div>";

    v.innerHTML = h;
    $$("[data-hw]", v).forEach(function (n) {
      var i = +n.getAttribute("data-hw");
      countUp(n, cards[i].vl, 560);
    });
  }

  /* ------------------------------------------------------------ 节点 */
  function renderNodes() {
    var v = $("#v-nd");
    if (!S.nd) {
      var first = SORTED.filter(function (a) { return a.state === "A" && a.exported > 0; })[0] ||
        SORTED.filter(function (a) { return a.nodes > 0; })[0];
      S.nd = first ? first.slug : (APTS[0] || {}).slug;
    }
    var q = S.q.toLowerCase();

    var list = APTS.slice().sort(function (x, y) {
      var o = (ORDER[x.state] == null ? 9 : ORDER[x.state]) - (ORDER[y.state] == null ? 9 : ORDER[y.state]);
      return o !== 0 ? o : (y.nodes - x.nodes);
    }).filter(function (a) { return !q || a.slug.toLowerCase().indexOf(q) >= 0; });

    var a = bySlug[S.nd] || APTS[0] || {};
    var rows = (a.node_rows || []).filter(function (r) {
      if (S.ndProto !== "all" && r[1] !== S.ndProto) return false;
      if (!q || S.q.length < 2) return true;
      return (r[0] + " " + r[1] + " " + r[2] + " " + r[3]).toLowerCase().indexOf(q) >= 0;
    });
    var protoCnt = {};
    (a.node_rows || []).forEach(function (r) { protoCnt[r[1]] = (protoCnt[r[1]] || 0) + 1; });

    var h = '<div class="nodes-grid"><div class="apt-list" id="aptList">';
    list.forEach(function (x) {
      h += '<button class="apt' + (x.slug === S.nd ? " on" : "") + '" data-slug="' + esc(x.slug) + '">' +
        dot(stCls(x.state)) + '<span class="an" title="' + esc(x.slug) + '">' + esc(nmOf(x)) + "</span>" +
        '<span class="ac">' + (x.nodes ? num(x.nodes) : "0") + "</span></button>";
    });
    h += "</div><div>";

    h += '<div class="node-head"><h2>' + esc(nmOf(a)) + enSuffix2(a) + "</h2>" +
      dot(stCls(a.state)) +
      '<span class="dim small">' + esc(stName(a.state)) + "</span>" +
      '<span class="pill">' + num(a.nodes) + " 节点</span>" +
      '<span class="pill t">可导出 ' + num(a.exported) + "</span>" +
      (a.via ? '<span class="pill v">' + esc(a.via) + "</span>" : "") +
      "</div>";

    h += '<div class="chips mt8" id="ppChips"><button class="chip' + (S.ndProto === "all" ? " on" : "") +
      '" data-pp="all">全部 <span class="n">' + (a.node_rows || []).length + "</span></button>";
    Object.keys(protoCnt).sort(function (x, y) { return protoCnt[y] - protoCnt[x]; }).forEach(function (p) {
      h += '<button class="chip' + (S.ndProto === p ? " on" : "") + '" data-pp="' + esc(p) + '">' + esc(p) +
        ' <span class="n">' + protoCnt[p] + "</span></button>";
    });
    h += "</div>";

    h += '<div class="sec mt8"><div class="sec-b tight node-scroll"><table class="tbl compact"><thead><tr>' +
      "<th>节点名</th><th>协议</th><th>服务器</th><th class=\"num\">端口</th><th>导出</th></tr></thead><tbody>";
    if (!rows.length) {
      h += '<tr><td colspan="5" class="dim">该机场当前没有落盘节点。' + esc(a.reason || "") + "</td></tr>";
    }
    rows.slice(0, 400).forEach(function (r) {
      h += "<tr" + (r[4] ? "" : ' class="dead"') + ">" +
        '<td class="nm">' + esc(r[0] || "—") + "</td>" +
        '<td><span class="pill"><i class="dotc" style="background:' + protoColor(r[1]) + '"></i>' + esc(r[1]) + "</span></td>" +
        '<td class="mono xsmall">' + esc(r[2]) + "</td>" +
        '<td class="num">' + (r[3] || "—") + "</td>" +
        "<td>" + (r[4] ? '<span class="pill ok">可导出</span>' : '<span class="pill">残片</span>') + "</td></tr>";
    });
    h += "</tbody></table>" + (rows.length > 400 ? '<div class="hint mt8">仅显示前 400 条，共 ' + num(rows.length) + " 条。</div>" : "") + "</div></div>";

    h += "</div></div>";
    v.innerHTML = h;

    $$("#aptList .apt", v).forEach(function (b) {
      b.addEventListener("click", function () {
        S.nd = b.getAttribute("data-slug");
        S.ndProto = "all";
        renderNodes();
        openDrawer(S.nd);
      });
    });
    $$("#ppChips .chip", v).forEach(function (b) {
      b.addEventListener("click", function () {
        S.ndProto = b.getAttribute("data-pp");
        renderNodes();
      });
    });
  }

  /* ------------------------------------------------------------ 机场库 */
  function _siteList() {
  var q = String(S.siteQ || "").toLowerCase();
  var out = (D.sites || []).slice();
  if (S.siteMon) out = out.filter(function (x) { return /已监控|域命中/.test(x.rel || ""); });
  if (q) {
    out = out.filter(function (x) {
      return (String(x.name || "") + " " + String(x.dom || "") + " " + String(x.protos || "") + " " + String(x.cat || "")).toLowerCase().indexOf(q) >= 0;
    });
  }
  out.sort(function (a, b) {
    var am = /已监控|域命中/.test(a.rel || "") ? 0 : 1;
    var bm = /已监控|域命中/.test(b.rel || "") ? 0 : 1;
    if (am !== bm) return am - bm;
    return String(b.date || "").localeCompare(String(a.date || ""));
  });
  return out;
}

function fillSiteBody() {
  var tb = $("#siteBody");
  if (!tb) return;
  var h = "";
  _siteList().forEach(function (x) {
    var rel = String(x.rel || "");
    var mine = /已监控|域命中/.test(rel);
    var dom = String(x.dom || "").replace(/^https?:\/\//, "").replace(/\/$/, "");
    h += "<tr>" +
      '<td class="nm">' + esc(x.name || "—") + "</td>" +
      '<td class="xsmall dim">' + esc(x.cat || "—") + "</td>" +
      '<td class="xsmall">' + (dom ? '<a href="https://' + esc(dom) + '" target="_blank" rel="noopener noreferrer">' + esc(dom) + "</a>" : "—") + "</td>" +
      '<td class="num xsmall dim">' + esc(String(x.date || "—").slice(0, 10)) + "</td>" +
      '<td class="xsmall dim">' + esc(x.free || "—") + "</td>" +
      '<td class="xsmall dim">' + esc(x.protos || "—") + "</td>" +
      "<td>" + (mine ? pill("pill ok", rel.replace(/;/g, " · ")) : '<span class="xsmall dim">未监控</span>') + "</td>" +
      "</tr>";
  });
  tb.innerHTML = h || '<tr><td colspan="7" class="dim xsmall">没有匹配的记录</td></tr>';
}

function renderLibrary() {
    var v = $("#v-lib");
    var q = S.q.toLowerCase();
    var list = APTS.filter(function (a) {
      if (S.lib === "sub" && a.type !== "sub") return false;
      if (S.lib === "client" && a.type !== "client") return false;
      if (S.lib === "bad" && a.state !== "D" && a.state !== "B") return false;
      if (!q) return true;
      return (a.slug + " " + (a.name_cn || "") + " " + (a.panel || "") + " " + (a.domains || []).join(" ") + " " + (a.client || "")).toLowerCase().indexOf(q) >= 0;
    });

    var h = '<div class="sec"><div class="sec-h"><h2>机场库</h2>' +
      '<span class="n">' + num(list.length) + " / " + num(APTS.length) + "</span><span class=\"sp\"></span>" +
      '<div class="chips" id="libChips">' +
      '<button class="chip' + (S.lib === "all" ? " on" : "") + '" data-lib="all">全部</button>' +
      '<button class="chip' + (S.lib === "sub" ? " on" : "") + '" data-lib="sub">订阅型</button>' +
      '<button class="chip' + (S.lib === "client" ? " on" : "") + '" data-lib="client">客户端型</button>' +
      '<button class="chip' + (S.lib === "bad" ? " on" : "") + '" data-lib="bad">异常</button>' +
      "</div>" +
      '<button class="btn xs primary" id="addAirport" title="买了新机场或注册了免费机场后，把它加进来">+ 添加机场</button>' +
      "</div>";

    h += '<div class="sec-b"><div class="cards">';
    list.forEach(function (a) {
      var cv = a.client_local ? ("v" + a.client_local) : "";
      var outdated = a.client_latest && a.client_local && a.client_latest !== a.client_local;
      h += '<div class="card" data-slug="' + esc(a.slug) + '">' +
        '<div class="c1">' + dot(stCls(a.state)) +
        '<span class="cn">' + esc(nmOf(a)) + enSuffix2(a) + "</span>" +
        '<span class="cv">' + (a.nodes ? num(a.nodes) + " / " + num(a.exported) : "0") + "</span></div>" +
        '<div class="c2">' + esc(a.panel || a.homepage || "—") + "</div>" +
        '<div class="c3">' +
        pill("pill " + stCls(a.state), stName(a.state)) +
        (a.type === "client" ? pill("pill v", (a.has_sub ? "客户端" : "仅客户端")) : pill("pill", "订阅")) +
        (a.days != null && a.days < 0 ? pill("pill d", "过期") : "") +
        (outdated ? pill("pill b", "客户端可升级") : "") +
        (a.idc_score != null ? pill("pill", "IDC " + a.idc_score) : "") +
        (a.probe_ok != null ? pill("pill", "探活 " + a.probe_ok + "/" + ((a.probe_ok || 0) + (a.probe_fail || 0))) : "") +
        "</div></div>";
    });
    h += "</div></div>";

    /* 推荐站档案：从评测站爬的 319 条 */
    var sites = D.sites || [];
    if (sites.length) {
      var mon = sites.filter(function (x) { return /已监控|域命中/.test(x.rel || ""); }).length;
      h += '<div class="sec mt14"><div class="sec-h"><h2>推荐站档案</h2>' +
        '<span class="n">' + sites.length + " 条 · 其中 " + mon + " 条与在监控的机场对得上</span>" +
        '<span class="sp"></span>' +
        '<input id="siteQ" class="qin" type="search" placeholder="搜机场名 / 域名 / 协议" value="' + esc(S.siteQ || "") + '">' +
        '<button class="chip' + (S.siteMon ? " on" : "") + '" id="siteMon">只看对得上的 (' + mon + ")</button>" +
        "</div>" +
        '<div class="sec-b tight"><div class="libsite"><table class="tbl compact"><thead><tr>' +
        "<th>机场名</th><th>栏目</th><th>域名</th><th>日期</th><th>套餐线索</th><th>协议</th><th>与我方关系</th>" +
        "</tr></thead><tbody id=\"siteBody\"></tbody></table></div></div></div>";
    }

    /* 免费 / 白菜价：没买，只监控域名是否还活着 */
    var fw = D.sitesFree || [];
    if (fw.length) {
      var fwAt = fw[0].at ? String(fw[0].at).slice(0, 10) : "—";
      var dead = fw.filter(function (x) { return !x.ok; }).length;
      h += '<div class="sec mt14"><div class="sec-h"><h2>免费 / 白菜价机场</h2>' +
        '<span class="n">' + fw.length + " 家 · 探测于 " + esc(fwAt) + (dead ? " · " + dead + " 家不可达" : "") + "</span>" +
        '<span class="sp"></span><span class="xsmall dim">没有账号，只监控官网域名是否还活着；确认要用的再去注册</span></div>' +
        '<div class="sec-b tight"><table class="tbl compact"><thead><tr>' +
        '<th>名称</th><th>类型</th><th class="num">状态</th><th>站点标题</th><th>说明</th><th>网址</th>' +
        "</tr></thead><tbody>";
      fw.forEach(function (x) {
        h += "<tr>" +
          '<td class="nm">' + esc(x.name) + "</td>" +
          "<td>" + pill("pill " + (x.tier === "cheap" ? "b" : "v"), x.tier === "cheap" ? "白菜价" : "免费") + "</td>" +
          '<td class="num">' + (x.ok ? '<span class="ok-t">' + esc(String(x.status || 200)) + "</span>"
                                    : '<span class="bad-t">' + esc(String(x.status || "不可达")) + "</span>") + "</td>" +
          '<td class="xsmall">' + esc(x.title || "—") + "</td>" +
          '<td class="xsmall dim">' + esc(x.note || "—") + "</td>" +
          '<td class="xsmall"><a href="https://' + esc(String(x.url || "").replace(/^\/+/, "")) + '" target="_blank" rel="noopener noreferrer">' +
            esc(String(x.url || "").replace(/\/$/, "")) + "</a></td>" +
          "</tr>";
      });
      h += "</tbody></table></div></div>";
    }

    h += "</div>";

    v.innerHTML = h;
    $$("#libChips .chip", v).forEach(function (b) {
      b.addEventListener("click", function () { S.lib = b.getAttribute("data-lib"); renderLibrary(); });
    });

    var ab = $("#addAirport");
    if (ab) ab.addEventListener("click", function (e) { e.stopPropagation(); openAddAirport(); });

    if ($("#siteBody")) {
      fillSiteBody();
      var qi = $("#siteQ");
      if (qi) qi.addEventListener("input", function () { S.siteQ = qi.value; fillSiteBody(); });
      var mb = $("#siteMon");
      if (mb) mb.addEventListener("click", function () {
        S.siteMon = !S.siteMon;
        mb.classList.toggle("on", S.siteMon);
        fillSiteBody();
      });
    }
    $$(".card", v).forEach(function (c) {
      c.addEventListener("click", function () { openDrawer(c.getAttribute("data-slug")); });
    });
  }

  /* ------------------------------------------------------------ 知识 */
  function renderKnowledge() {
    var v = $("#v-kn");
    var all = D.knowledge || [];
    var cats = {};
    all.forEach(function (k) { cats[k.cat] = (cats[k.cat] || 0) + 1; });
    var q = S.q.toLowerCase();
    var list = all.filter(function (k) {
      if (S.kn !== "all" && k.cat !== S.kn) return false;
      if (!q) return true;
      return (k.title + " " + k.excerpt + " " + (k.doms || []).join(" ")).toLowerCase().indexOf(q) >= 0;
    });

    var h = '<div class="sec"><div class="sec-h"><h2>知识库</h2>' +
      '<span class="n">' + num(all.length) + " 篇</span><span class=\"sp\"></span>" +
      '<div class="chips" id="knChips"><button class="chip' + (S.kn === "all" ? " on" : "") + '" data-kn="all">全部</button>';
    Object.keys(cats).forEach(function (c) {
      h += '<button class="chip' + (S.kn === c ? " on" : "") + '" data-kn="' + esc(c) + '">' + esc(c) +
        ' <span class="n">' + cats[c] + "</span></button>";
    });
    h += "</div></div>";

    h += '<div class="sec-b"><div class="kn-grid">';
    list.forEach(function (k) {
      h += '<article class="kn"><div class="k1">' + pill("pill v", esc(k.cat || "—")) +
        "<span>" + esc(k.date || "") + "</span><span>· " + (k.n || 0) + " 节</span></div>" +
        "<h3>" + esc(k.title) + "</h3><p>" + esc(k.excerpt || "—") + "</p>" +
        '<div class="k3">' + (k.doms || []).slice(0, 4).map(function (d) { return pill("pill", esc(d)); }).join("") + "</div></article>";
    });
    h += "</div></div></div>";
    v.innerHTML = h;

    $$("#knChips .chip", v).forEach(function (b) {
      b.addEventListener("click", function () { S.kn = b.getAttribute("data-kn"); renderKnowledge(); });
    });
  }

  /* ------------------------------------------------------------ 分析 */
  function renderAnalysis() {
    var v = $("#v-an");
    var ser = D.series || {};
    var dates = ser.dates || [];
    var vals = ser.values || [];

    var h = '<div class="sec"><div class="sec-h"><h2>最近 30 天节点总量</h2>' +
      '<span class="n">' + esc(D.meta.base || "") + " · 基线 " + (dates[0] || "") + " 起</span></div>" +
      '<div class="sec-b">' + lineChart(dates, vals) + "</div></div>";

    h += '<div class="grid2 mt14">' + barBlock("协议构成", D.protos || [], protoColor, "节点") +
      barBlock("地区分布", D.geos || [], null, "节点") + "</div>";

    /* RDAP 组织聚合 */
    var orgs = {};
    Object.keys(D.rdap || {}).forEach(function (slug) {
      var r = D.rdap[slug] || {};
      var o = r.top_org || "未知";
      if (!orgs[o]) orgs[o] = { n: 0, nodes: 0, slugs: [] };
      orgs[o].n += 1;
      orgs[o].nodes += r.nodes || 0;
      orgs[o].slugs.push(slug);
    });
    var orgArr = Object.keys(orgs).map(function (o) { return { org: o, n: orgs[o].n, nodes: orgs[o].nodes, slugs: orgs[o].slugs }; })
      .sort(function (a, b) { return b.nodes - a.nodes; }).slice(0, 12);

    var h2 = '<div class="sec"><div class="sec-h"><h2>落地机房（RDAP 组织）</h2>' +
      '<span class="n">节点数排序</span></div><div class="sec-b tight"><table class="tbl compact"><thead><tr>' +
      '<th>组织</th><th class="num">节点</th><th class="num">机场</th><th>机场</th></tr></thead><tbody>';
    orgArr.forEach(function (o) {
      h2 += '<tr><td class="nm">' + esc(o.org) + '</td><td class="num">' + num(o.nodes) +
        '</td><td class="num">' + o.n + '</td><td class="xsmall dim">' + esc(o.slugs.slice(0, 6).join("、")) + "</td></tr>";
    });
    h2 += "</tbody></table></div></div>";

    var h3 = '<div class="sec"><div class="sec-h"><h2>波动最大</h2><span class="n">30 天累计增删</span></div>' +
      '<div class="sec-b tight"><table class="tbl compact"><thead><tr><th>机场</th><th class="num">累计波动</th><th class="num">最新</th></tr></thead><tbody>';
    (D.churn || []).slice(0, 12).forEach(function (c) {
      h3 += '<tr><td class="nm" title="' + esc(c.slug) + '">' + esc(nmBySlug(c.slug)) + '</td><td class="num">' + num(c.churn) +
        '</td><td class="num">' + num(c.latest) + "</td></tr>";
    });
    h3 += "</tbody></table></div></div>";

    h += '<div class="grid2 mt14">' + h2 + h3 + "</div>";

    var h4 = '<div class="sec"><div class="sec-h"><h2>零节点最多</h2><span class="n">30 天内返回 0 节点的次数</span></div>' +
      '<div class="sec-b tight"><table class="tbl compact"><thead><tr><th>机场</th><th class="num">0 节点次数</th></tr></thead><tbody>';
    (D.zero || []).slice(0, 12).forEach(function (z) {
      h4 += '<tr><td class="nm">' + esc(z.slug) + '</td><td class="num">' + num(z.zero_n) + "</td></tr>";
    });
    h4 += "</tbody></table></div></div>";

    var h5 = '<div class="sec"><div class="sec-h"><h2>稳定性最差</h2><span class="n">有数据的天数占比</span></div>' +
      '<div class="sec-b tight"><table class="tbl compact"><thead><tr><th>机场</th><th class="num">占比</th><th class="num">有数据/总天数</th></tr></thead><tbody>';
    (D.stability || []).slice().sort(function (a, b) { return a.pct - b.pct; }).slice(0, 12).forEach(function (s) {
      h5 += '<tr><td class="nm">' + esc(s.slug) + '</td><td class="num"><span class="' +
        (s.pct < 50 ? "pill d" : s.pct < 80 ? "pill b" : "pill t") + '">' + s.pct + "%</span></td>" +
        '<td class="num dim">' + s.ok_days + " / " + s.days + "</td></tr>";
    });
    h5 += "</tbody></table></div></div>";

    h += '<div class="grid2 mt14">' + h4 + h5 + "</div>";
    v.innerHTML = h;
  }

  function lineChart(dates, vals) {
    var W = 900, H = 168, pad = { l: 40, r: 12, t: 12, b: 22 };
    if (!vals.length) return '<div class="hint">暂无时序数据</div>';
    var max = Math.max.apply(null, vals) || 1;
    var min = Math.min.apply(null, vals);
    var lo = Math.max(0, min - (max - min) * 0.25);
    var iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
    var x = function (i) { return pad.l + (vals.length < 2 ? iw / 2 : (i / (vals.length - 1)) * iw); };
    var y = function (v) { return pad.t + ih - ((v - lo) / (max - lo || 1)) * ih; };

    var d = "";
    vals.forEach(function (v, i) { d += (i ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1) + " "; });
    var area = d + "L" + x(vals.length - 1).toFixed(1) + " " + (pad.t + ih) + " L" + x(0).toFixed(1) + " " + (pad.t + ih) + " Z";

    var g = "";
    for (var k = 0; k <= 3; k++) {
      var gy = pad.t + (ih / 3) * k;
      var gv = Math.round(max - ((max - lo) / 3) * k);
      g += '<line class="gr" x1="' + pad.l + '" y1="' + gy + '" x2="' + (W - pad.r) + '" y2="' + gy + '"/>';
      g += '<text class="tx" x="' + (pad.l - 6) + '" y="' + (gy + 3.5) + '" text-anchor="end">' + gv + "</text>";
    }
    var idxs = [0, Math.floor(vals.length / 2), vals.length - 1];
    idxs.forEach(function (i) {
      if (dates[i] == null) return;
      g += '<text class="tx" x="' + x(i) + '" y="' + (H - 6) + '" text-anchor="' + (i === 0 ? "start" : i === vals.length - 1 ? "end" : "middle") + '">' + esc(String(dates[i]).slice(5)) + "</text>";
    });

    return '<svg class="chart" viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="30 天节点总量">' +
      '<defs><linearGradient id="gTeal" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" stop-color="#3ee0b0" stop-opacity=".28"/><stop offset="1" stop-color="#3ee0b0" stop-opacity="0"/></linearGradient></defs>' +
      g + '<path class="ar" d="' + area + '"/><path class="ln" d="' + d + '"/></svg>';
  }

  /* ------------------------------------------------------------ 运行 */
  function renderRun() {
    var v = $("#v-run");
    var r = D.meta.round || {};
    var ok = typeof r.pull_ok === "number" ? r.pull_ok : null;
    var fail = typeof r.pull_fail === "number" ? r.pull_fail : null;
    var dur = r.duration_s ? (r.duration_s / 60).toFixed(1) + " 分钟" : "—";

    var h = "";
    var wd = API.wd;
    if (wd) {
      var bad = wd.healthy === false;
      var probs = wd.problems || [];
      h += '<div class="sec" style="border-color:' + (bad ? "var(--red)" : "var(--line)") + '">' +
        '<div class="sec-h"><h2>健康体检</h2><span class="n">' +
        (wd.heartbeat_age_min != null ? "心跳 " + wd.heartbeat_age_min.toFixed(1) + " 分钟前" : "无心跳") + "</span></div>" +
        '<div class="sec-b tight"><div class="row wrap" style="gap:8px;align-items:center">' +
        pill(bad ? "pill r" : "pill g", bad ? "异常 " + probs.length + " 项" : "健康") +
        pill(wd.round_running ? "pill t" : "pill", wd.round_running ? "轮次在跑" : "当前无轮次") +
        (wd.heartbeat_step ? pill("pill", esc(wd.heartbeat_step)) : "") +
        (wd.heartbeat_progress ? pill("pill b", esc(wd.heartbeat_progress) + " 家") : "") +
        (wd.heartbeat_airport ? '<span class="dim small">当前 ' + esc(wd.heartbeat_airport) + "</span>" : "") +
        "</div>";
      if (probs.length) {
        h += '<table class="tbl compact" style="margin-top:8px"><thead><tr><th>问题</th><th>说明</th><th>怎么处理</th></tr></thead><tbody>';
        probs.forEach(function (p) {
          h += '<tr><td class="mono xsmall">' + esc(p.kind) + "</td><td>" + esc(p.summary || "") +
               '</td><td class="xsmall dim">' + esc(p.fix || "—") + "</td></tr>";
        });
        h += "</tbody></table>";
      } else {
        h += '<div class="dim small" style="margin-top:6px">锁、心跳、台账三者一致：没有僵尸锁、没有卡死、上一轮正常收尾。</div>';
      }
      h += "</div></div>";
    }
    h += '<div class="kpis' + (h ? ' mt14' : '') + '" style="grid-template-columns:repeat(5,minmax(0,1fr))">' +
      '<div class="kpi ' + (r.status === "ok" ? "ok" : "b") + '"><div class="lb">本轮状态</div><div class="vl" style="font-size:22px">' + esc(r.status || "—") + '</div><div class="ft">' + esc(r.step || "") + "</div></div>" +
      '<div class="kpi"><div class="lb">耗时</div><div class="vl" style="font-size:22px">' + esc(dur) + '</div><div class="ft">' + esc(shortTime(r.started_at)) + " → " + esc(shortTime(r.ended_at)) + "</div></div>" +
      '<div class="kpi ok"><div class="lb">拉取成功</div><div class="vl" style="font-size:22px">' + (ok == null ? "—" : num(ok)) + '</div><div class="ft">家机场</div></div>' +
      '<div class="kpi d"><div class="lb">拉取失败</div><div class="vl" style="font-size:22px">' + (fail == null ? "—" : num(fail)) + '</div><div class="ft">含网络抖动</div></div>' +
      '<div class="kpi t"><div class="lb">采集节点</div><div class="vl" style="font-size:22px">' + (r.nodes_total == null ? num(T.nodes) : num(r.nodes_total)) + '</div><div class="ft">华为命中 ' + (r.hw_findings == null ? "—" : r.hw_findings) + "</div></div>" +
      "</div>";

    /* 代理可达性：哪些订阅直连就能拉、哪些非走代理不可 */
    var pm = D.proxy_meta || {};
    var pAgg = { direct: [], direct_fail: [], proxy: [], both: [], none: [], nosub: [] };
    (D.airports || []).forEach(function (a) {
      var pk2 = (a.proxy && a.proxy.sub) || (a.has_sub ? "" : "nosub");
      if (!pk2) return;
      if (!pAgg[pk2]) pAgg[pk2] = [];
      pAgg[pk2].push(a);
    });
    h += '<div class="sec mt14"><div class="sec-h"><h2>代理可达性</h2><span class="n">' +
      (pm.at ? "探测于 " + esc(pm.at) + " · " + (pm.proxy_alive ? "代理当时可用" : "代理当时未开") : "还没有探测数据") +
      '</span></div><div class="sec-b tight">';
    if (!pm.at) {
      h += '<span class="dim small">跑一次 <span class="mono">python -X utf8 tools/proxy_need.py</span> 才知道哪几家非走代理不可。</span>';
    } else {
      var dOk = pAgg.direct.length + pAgg.both.length;
      var dBad = pAgg.direct_fail.length + pAgg.none.length;
      h += '<div class="row wrap" style="gap:6px">' +
        pill("pill g", "直连即可 " + dOk + " 家") +
        pill("pill t", "直连不通 " + dBad + " 家") +
        pill("pill", "无订阅（客户端型）" + pAgg.nosub.length + " 家") +
        (!pm.proxy_alive ? pill("pill r", "代理未开 · 需代理组未测") : "") +
        "</div>";
      if (dBad) {
        h += '<div class="small fg2" style="margin-top:8px">直连不通：' +
          esc(pAgg.direct_fail.concat(pAgg.none).map(function (a) { return a.slug; }).join("、")) + "</div>" +
          '<div class="xsmall dim" style="margin-top:4px">SSL 握手失败多是墙外订阅域（需代理）；403/504 是站点自己拦或挂了，开代理也未必通。</div>';
      }
      var byProxy = pAgg.proxy.map(function (a) { return a.slug; });
      if (byProxy.length) {
        h += '<div class="xsmall dim" style="margin-top:4px">只能靠代理：' + esc(byProxy.join("、")) + "</div>";
      }
    }
    h += "</div></div>";

    var runs = D.runs || [];
    h += '<div class="sec mt14"><div class="sec-h"><h2>历史轮次</h2><span class="n">最近 ' + runs.length + ' 轮 · 点一行看本轮失败名单</span></div><div class="sec-b tight">';
    if (!runs.length) {
      h += '<span class="dim small">还没有轮次记录：run.py 从下一轮起会把摘要写进 data/runs.json。</span>';
    } else {
      h += '<table class="tbl compact" id="runsTbl"><thead><tr><th>开始</th><th>耗时</th><th>触发</th><th>结果</th><th>成功/失败</th><th class="r">节点</th><th class="r">陈旧</th></tr></thead><tbody>';
      runs.slice().reverse().forEach(function (x, i) {
        var du = x.duration_s ? (x.duration_s / 60).toFixed(1) + "m" : "—";
        var stc = x.derived ? "pill" : (x.status === "ok" ? "pill ok" : "pill d");
        var stt = x.derived ? "还原" : esc(x.status || "—");
        var nf = (x.failed || []).length;
        h += '<tr class="rrow" data-i="' + i + '"' + (nf ? ' style="cursor:pointer"' : "") + '>' +
          '<td class="mono xsmall">' + esc(shortTime(x.started_at)) + "</td>" +
          '<td class="mono xsmall">' + du + "</td>" +
          '<td class="xsmall dim">' + (x.trigger === "scheduled" ? "定时" : "手动") + "</td>" +
          "<td>" + pill(stc, stt) + "</td>" +
          '<td class="mono xsmall">' + (x.pull_ok == null ? "—" : x.pull_ok) + " / " + (x.pull_fail == null ? "—" : x.pull_fail) + "</td>" +
          '<td class="r mono">' + (x.nodes_total == null ? "—" : num(x.nodes_total)) + "</td>" +
          '<td class="r mono ' + (x.stale_n ? "" : "dim") + '">' + (x.stale_n == null ? "—" : x.stale_n) + "</td></tr>";
        if (nf) {
          h += '<tr class="rdet" data-i="' + i + '" style="display:none"><td colspan="7" class="xsmall dim" style="padding-left:20px">' +
            nf + " 家失败：" +
            esc(x.failed.slice(0, 18).map(function (f) {
              return (f && typeof f === "object") ? (f.slug + (f.reason ? "（" + String(f.reason).slice(0, 28) + "）" : "")) : String(f);
            }).join("、")) + (nf > 18 ? " …" : "") + "</td></tr>";
        }
      });
      h += "</tbody></table></div></div>";
    }

    var stale = r.stale || [];
    h += '<div class="sec"><div class="sec-h"><h2>陈旧机场</h2><span class="n">最近快照超过 6 小时</span></div><div class="sec-b">';
    if (stale.length) {
      h += '<div class="row wrap" style="gap:6px">' + stale.map(function (s) { return pill("pill b", esc(s)); }).join("") + "</div>";
    } else {
      h += '<span class="dim small">全部机场都在 6 小时内更新过。</span>';
    }
    h += "</div></div>";

    var tail = D.logTail || [];
    h += '<div class="sec mt14"><div class="sec-h"><h2>运行日志</h2><span class="n">run.log 尾部 ' + tail.length + " 行 · 地址与凭据已隐</span></div>" +
      '<div class="sec-b tight"><pre class="mono xsmall" style="margin:0;max-height:300px;overflow:auto;line-height:1.75;color:var(--fg2)">' +
      esc(tail.join("\n")) + "</pre></div></div>";

    var cl = D.clients || [];
    h += '<div class="sec mt14"><div class="sec-h"><h2>客户端版本</h2><span class="n">' + cl.length + " 台</span></div>" +
      '<div class="sec-b tight"><table class="tbl compact"><thead><tr><th>机场</th><th>客户端</th><th>本地版本</th><th>最新</th><th>状态</th><th>节点</th></tr></thead><tbody>';
    cl.forEach(function (c) {
      var lag = c.latest_ver && c.local_ver && c.latest_ver !== c.local_ver;
      h += '<tr><td class="nm" title="' + esc(c.slug) + '">' + esc(nmBySlug(c.slug)) + "</td><td>" + esc(c.client || "—") + "</td>" +
        '<td class="mono">' + esc(c.local_ver || "—") + "</td>" +
        '<td class="mono ' + (lag ? "" : "dim") + '">' + esc(c.latest_ver || "—") + "</td>" +
        "<td>" + pill(lag ? "pill b" : "pill", lag ? "可升级" : esc(c.status || "—")) + "</td>" +
        '<td class="xsmall dim">' + esc((c.node_pull || "").slice(0, 40)) + "</td></tr>";
    });
    h += "</tbody></table></div></div>";

    var raws = (D.airports || []).filter(function (a) { return a.raw && a.raw.at; })
      .sort(function (a, b) { return String(b.raw.at).localeCompare(String(a.raw.at)); });
    h += '<div class="sec mt14"><div class="sec-h"><h2>订阅原文存档</h2><span class="n">' + raws.length + " 家 · 正文含凭据，只在此处显示元信息</span></div>" +
      '<div class="sec-b tight">';
    if (!raws.length) {
      h += '<span class="dim small">还没有存档：订阅型机场每次拉取都会把原始响应存到 data/subraw/&lt;机场&gt;/（每台保留最近 30 份）。</span>';
    } else {
      h += '<table class="tbl compact"><thead><tr><th>机场</th><th>最近一份</th><th>格式</th><th class="r">大小</th><th>通道</th><th></th></tr></thead><tbody>';
      raws.forEach(function (a) {
        var kb = a.raw.bytes ? (a.raw.bytes / 1024).toFixed(1) + " KB" : "—";
        h += '<tr><td class="nm">' + esc(nmOf(a)) + "</td>" +
          '<td class="mono xsmall">' + esc(shortTime(a.raw.at)) + "</td>" +
          '<td class="mono xsmall">' + esc(a.raw.ext || "—") + "</td>" +
          '<td class="r mono xsmall">' + kb + "</td>" +
          '<td class="xsmall dim">' + esc(a.raw.via || "—") + "</td>" +
          '<td class="r"><button class="btn ghost xs raws" data-slug="' + esc(a.slug) + '">看原文</button></td></tr>';
      });
      h += "</tbody></table></div></div>";
    }

    v.innerHTML = h;
    $$("button.raws").forEach(function (b) {
      b.addEventListener("click", function () {
        var slug = b.getAttribute("data-slug");
        b.textContent = "读取中…";
        fetch("api/raw/" + encodeURIComponent(slug) + "?limit=300000", { cache: "no-store" })
          .then(function (r) { return r.json(); })
          .then(function (j) {
            b.textContent = "看原文";
            if (!j.ok) { toast(j.error || "读取失败"); return; }
            var m = j.meta || {};
            openModal("订阅原文 · " + slug + " · " + (m.at || "") + " · " + (m.bytes ? (m.bytes / 1024).toFixed(1) + " KB" : ""), j.text || "");
          })
          .catch(function () { b.textContent = "看原文"; toast("预览服务未启动或不可达"); });
      });
    });
    $$("#runsTbl .rrow").forEach(function (tr) {
      tr.addEventListener("click", function () {
        var i = tr.getAttribute("data-i");
        var d = $("#runsTbl").querySelector('.rdet[data-i="' + i + '"]');
        if (d) d.style.display = d.style.display === "none" ? "" : "none";
      });
    });
  }

  /* ------------------------------------------------------------ 弹窗与轻提示 */
  function toast(msg) {
    var t = $("#toast");
    if (!t) return;
    t.textContent = msg;
    t.className = "on";
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.className = ""; }, 3400);
  }

  function openModal(title, text) {
    $("#mdlT").textContent = title || "";
    $("#mdlB").textContent = text || "";
    $("#mdl").classList.add("on");
  }

  function openModalHtml(title, html) {
    $("#mdlT").textContent = title || "";
    $("#mdlB").innerHTML = html || "";
    $("#mdl").classList.add("on");
  }

  /* ── 添加监控机场 ───────────────────────────────────────── */
  function _fRow(id, label, ph, req, val) {
    return '<label class="fr"><span>' + label + (req ? ' <i class="req">*</i>' : "") + "</span>" +
      '<input id="' + id + '" type="text" placeholder="' + (ph || "") + '" value="' + esc(val || "") + '"' +
      (req ? ' required' : "") + "></label>";
  }

  function openAddAirport() {
    var html = '<form id="addForm" class="addf" autocomplete="off">' +
      '<p class="fhint">买了一个机场，或注册了免费机场？把面板地址或订阅链接填进来，下一轮定时任务就会自动带上它。' +
      "填写后会先校验、再备份 <code>airports.yaml</code> / <code>credentials.yaml</code>，然后写入。</p>" +
      _fRow("fSlug", "标识（英文小写，2–32 位）", "例如 glados2 或 myairport", true) +
      _fRow("fDisp", "显示名（中文名，可不填）", "例如 快柠檬") +
      _fRow("fPanel", "面板地址", "https://example.com/#/login") +
      _fRow("fSub", "订阅链接", "https://…/api/v1/client/subscribe?key=…") +
      _fRow("fMail", "登录邮箱（可不填）", "填写注册用的邮箱") +
      _fRow("fPass", "登录密码（可不填）", "仅在自动登录/刷新订阅时用") +
      '<label class="fr"><span>类型</span><select id="fType">' +
        '<option value="auto">自动判断（推荐）</option>' +
        '<option value="direct">订阅直连</option>' +
        '<option value="client">客户端型（要开客户端）</option>' +
      "</select></label>" +
      '<label class="fchk"><input id="fGo" type="checkbox" checked> 添加后立即获取一次节点</label>' +
      '<div class="fmsg" id="fMsg"></div>' +
      '<div class="fact"><button type="submit" class="btn primary" id="fOk">添加并保存</button>' +
      '<button type="button" class="btn" id="fCancel">取消</button></div>' +
      "</form>";
    openModalHtml("添加监控机场", html);
    var f = $("#addForm");
    if (f) f.addEventListener("submit", function (e) { e.preventDefault(); submitAddAirport(); });
    var c = $("#fCancel");
    if (c) c.addEventListener("click", closeModal);
  }

  function _fMsg(html, cls) {
    var m = $("#fMsg");
    if (m) { m.className = "fmsg " + (cls || ""); m.innerHTML = html; }
  }

  function submitAddAirport() {
    var body = {
      slug: ($("#fSlug") || {}).value || "",
      display: ($("#fDisp") || {}).value || "",
      panel: ($("#fPanel") || {}).value || "",
      sub_url: ($("#fSub") || {}).value || "",
      email: ($("#fMail") || {}).value || "",
      pw: ($("#fPass") || {}).value || "",
      type: ($("#fType") || {}).value || "auto"
    };
    var go = $("#fGo") && $("#fGo").checked;
    var ok = $("#fOk");
    if (ok) { ok.disabled = true; ok.textContent = "写入中…"; }
    _fMsg("正在校验并写入配置文件…", "");
    fetch("api/airports/add", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (!d.ok) {
        _fMsg('<b style="color:var(--red)">没写成功：</b>' + esc(d.error || "未知错误"), "bad");
        if (ok) { ok.disabled = false; ok.textContent = "添加并保存"; }
        return;
      }
      _fMsg('<b style="color:var(--green)">已加入监控：</b>' + esc(d.display || d.slug) +
        "（" + esc(d.slug) + "）" + (d.has_sub ? "" : " · 没有订阅链接，将走面板登录或客户端") +
        (go ? " · 正在获取节点…"
            : (d.regen === "ok"
                ? " · 已进入总览（暂无节点，等定时任务或点卡片里的「获取节点」）"
                : " · 配置已写入，但面板数据没重生成功，稍后手动刷新一次")), "ok");
      if (!go) {
        /* 服务端已经把 data.js 重生过了，这里 reloadData 就能看到新卡片 */
        setTimeout(function () { closeModal(); reloadData(); toast("已加入总览：" + (d.display || d.slug)); }, 900);
        return;
      }
      fetch("api/fetch/" + encodeURIComponent(d.slug), { method: "POST" })
        .then(function (r) { return r.json(); })
        .then(function () {
          var n = 0;
          var t = setInterval(function () {
            n += 1;
            reloadData();
            if (n >= 10) {
              clearInterval(t);
              closeModal();
              toast("「" + (d.display || d.slug) + "」已添加，节点获取完成，看卡片状态");
            }
          }, 5000);
        })
        .catch(function () { closeModal(); reloadData(); });
    }).catch(function (e) {
      _fMsg('<b style="color:var(--red)">请求失败：</b>' + esc(String(e)), "bad");
      if (ok) { ok.disabled = false; ok.textContent = "添加并保存"; }
    });
  }

  function closeModal() {
    $("#mdl").classList.remove("on");
  }

  function initModal() {
    var x = $("#mdlX"), m = $("#mdl");
    if (x) x.addEventListener("click", closeModal);
    if (m) m.addEventListener("click", function (e) { if (e.target === m) closeModal(); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeModal();
    });
  }

  /* ------------------------------------------------------------ 右栏待办 */
  function renderRail() {
    var acts = (D.actions || []);
    var h = "";
    acts.forEach(function (a) {
      var cls = stCls(a.state);
      h += '<div class="act" data-slug="' + esc(a.slug) + '">' +
        '<i class="rd" style="background:' + ({ ok: "#35d08a", b: "#f2b33d", c: "#5c8bff", d: "#f0555c" }[cls] || "#757d8d") + '"></i>' +
        '<div><div class="t1">' + esc(nmOf(a)) + '<span class="d">' + esc(stName(a.state)) +
        (a.days != null ? " · " + (a.days < 0 ? "过期" + (-a.days) + "天" : a.days + "天") : "") + "</span></div>" +
        '<div class="t2">' + esc(a.reason || "—") + "</div>" +
        (a.action ? '<div class="t3">' + esc(a.action) + "</div>" : "") +
        "</div></div>";
    });
    if (!h) h = '<div class="act"><div></div><div class="t2">本轮没有需要人工介入的项。</div></div>';
    $("#actList").innerHTML = h;
    $("#actN").textContent = acts.length + " 项";
    $$("#actList .act").forEach(function (n) {
      n.addEventListener("click", function () { openDrawer(n.getAttribute("data-slug")); });
    });
  }

  /* ------------------------------------------------------------ 抽屉 */
  function openDrawer(slug) {
    var a = bySlug[slug];
    if (!a) return;
    $("#drTitle").innerHTML = esc(nmOf(a)) + enSuffix2(a);
    $("#drSub").textContent = (a.type === "client" ? "客户端型" : "订阅型") + " · " + stName(a.state) +
      (a.panel ? " · " + a.panel : "");

    var used = (a.total_gb != null && a.used_pct != null) ? Math.round(a.total_gb * a.used_pct / 100) : null;
    var kv = [
      ["状态", dot(stCls(a.state)) + " " + stName(a.state)],
      ["可用节点", num(a.nodes) + (a.frag ? " 条（另有 " + num(a.frag) + " 条无协议碎片）" : " 条") + " · 可导出 " + num(a.exported)],
      ["获取方式", esc(a.via || "—") + (a.client_age_h != null
        ? (a.client_age_h >= 6
            ? ' <span class="tag old" title="抓取回来已经过去很久，每个节点的 servername(SNI) 每轮订阅都会重新随机 —— 超过 6 小时的很可能连不通">缓存 ' + a.client_age_h + ' 小时前</span>'
            : ' <span class="xsmall dim">' + a.client_age_h + ' 小时前抓取</span>')
        : "")],
      ["套餐到期", esc(a.expire || "—") + (a.days != null ? "（" + esc(daysText(a.days)) + "）" : "")],
      ["流量", a.unlimited ? "不限量" : (a.total_gb != null ? num(used) + " / " + num(a.total_gb) + " GB（" + (a.used_pct || 0) + "%）" : "—")],
      ["最近成功", '<span id="apLastOk">' + esc(relTime(a.last_ok)) + "</span>"],
      ["快照年龄", a.stale_h != null ? a.stale_h + " 小时" : "—"],
      ["30 天稳定", a.stability != null ? a.stability + "%" : "—"],
      ["累计波动", num(a.churn || 0)],
      ["落地机房", esc(a.rdap_org || "—") + (a.rdap_share != null ? "（" + Math.round(a.rdap_share * 100) + "%）" : "")],
      ["承载/CDN", infraText(a)],
      ["IDC 特征", a.idc_score != null ? a.idc_score + " · " + esc(a.idc_level || "") : "—"],
      ["探活", a.probe_ok != null ? a.probe_ok + " 通 / " + a.probe_fail + " 失败" : "—"],
      ["客户端", a.client ? esc(a.client) + " v" + esc(a.client_local || "?") + (a.client_latest ? " → " + esc(a.client_latest) : "") : "—"],
      ["订阅入口", (function () {
        var pk = (a.proxy && a.proxy.sub) || "";
        if (!pk) return a.has_sub ? "—" : "无订阅（客户端型）";
        var map = {
          direct: ["直连即可", "var(--green)"],
          both: ["直连/代理均可", "var(--green)"],
          proxy: ["需代理", "var(--amber)"],
          direct_fail: ["直连不通 · 需代理", "var(--amber)"],
          none: ["直连与代理都不通", "var(--red)"]
        };
        var m2 = map[pk] || [pk, ""];
        return '<span style="color:' + m2[1] + '">' + esc(m2[0]) + "</span>";
      })()],
      ["面板", esc(a.panel || "—")],
      ["域名", (a.domains || []).length ? esc((a.domains || []).join("、")) : "—"]
    ];

    var h = "";

    /* 机场信息（面板 / 订阅链接 / 客户端），数据来自本地预览后端 */
    h += '<div class="sub-h">机场信息</div>' +
      '<div class="apwrap" id="apInfo"><div class="aprow"><div class="apk">读取中</div>' +
      '<div class="apv dim" id="apInfoMsg">正在向本地预览服务取面板与订阅…</div></div></div>';

    /* 获取节点：真跑 run.py pull --airport <slug> */
    h += '<div class="sub-h">获取节点</div>' +
      '<div class="row" style="gap:8px;align-items:center">' +
      '<button class="btn primary" id="apFetch">获取节点</button>' +
      '<span class="small dim" id="apFetchMsg"></span></div>' +
      '<div class="logbox" id="apLog" style="display:none"></div>';

    /* 原始文件：订阅下载下来那一坨 / 我们解析后的快照 / 导出配置，都打码后可看 */
    h += '<div class="sub-h">原始文件</div>' +
      '<div class="row wrap" style="gap:8px">' +
      '<button class="btn xs" id="apFileRaw">订阅原文</button>' +
      '<button class="btn xs" id="apFileSnap">解析后快照</button>' +
      '<button class="btn xs" id="apFileYaml">导出配置</button>' +
      '<span class="small dim">密码/uuid/令牌已打码</span></div>';

    if (a.sub_closed && a.sub_closed.at) {
      var auto = a.sub_auto && a.sub_auto.ok
        ? "下一次拉取会自动开启（面板令牌剩 " + num(a.sub_auto.hours) + " 小时）"
        : "面板令牌已过期或未配置 —— 去面板点「开启订阅」，再复制 localStorage 的 pu:auth 填到 credentials.yaml";
      kv.unshift(["订阅状态", '<span class="bad">关闭中（' + esc(a.sub_closed.at) + "）</span> · " + auto]);
    }
    if (a.sub_auto && a.sub_auto.ok) {
      kv.unshift(["面板令牌", num(a.sub_auto.hours) + " 小时后过期" +
        (a.sub_auto.hours < 48 ? ' · <span class="bad">快过期了，记得重新复制</span>' : "")]);
    }
    h += '<dl class="kv">';
    kv.forEach(function (p) { h += "<dt>" + p[0] + "</dt><dd>" + p[1] + "</dd>"; });
    h += "</dl>";

    if (a.reason) {
      h += '<div class="sub-h">本轮判定</div><div class="small fg2">' + esc(a.reason) + "</div>";
    }
    if (a.action) {
      h += '<div class="sub-h">需要你做什么</div><div class="small" style="color:var(--teal)">' + esc(a.action) + "</div>";
    }

    /* 协议分布 */
    var pr = a.protos || {};
    var pk = Object.keys(pr);
    if (pk.length) {
      var tot = pk.reduce(function (s, k) { return s + pr[k]; }, 0) || 1;
      h += '<div class="sub-h">节点协议</div><div class="row wrap" style="gap:6px">';
      pk.sort(function (x, y) { return pr[y] - pr[x]; }).forEach(function (k) {
        h += '<span class="pill"><i class="dotc" style="background:' + protoColor(k) + '"></i>' + esc(k) + " " + pr[k] + " · " + pct(pr[k], tot) + "%</span>";
      });
      h += "</div>";
    }

    /* 已知域名全集 */
    var doms = a.doms_all || [];
    if (doms.length) {
      h += '<div class="sub-h">已知域名（' + doms.length + ' 个 · 当前可打开 ' + (a.doms_alive || 0) + ' 个）</div>';
      h += '<div class="nodewrap"><table class="tbl compact nodetbl domtbl"><thead><tr>' +
        '<th>域名</th><th class="thc">状态</th><th>标题 / 来源</th></tr></thead><tbody>';
      doms.forEach(function (x) {
        var alive = x.c === 200;
        var code = alive ? "200" : (x.c === "不通" ? "不通" : String(x.c));
        var srcs = (x.s || []).join(" · ");
        h += "<tr>" +
          '<td class="mono xsmall"><a class="link" href="' + (alive ? "https://" + esc(x.d) : "#") + '"' +
          (alive ? ' target="_blank" rel="noreferrer"' : "") + ">" + esc(x.d) + "</a></td>" +
          '<td class="xsmall thc ' + (alive ? "okc" : "dim") + '">' + esc(code) + "</td>" +
          '<td class="xsmall dim">' + (x.t ? esc(x.t) + (srcs ? " — " : "") : "") + esc(srcs) + "</td>" +
          "</tr>";
      });
      h += "</tbody></table></div>";
    } else {
      h += '<div class="sub-h">已知域名</div><div class="small dim">还没有收录到这家除面板以外的域名。</div>';
    }

    /* 最近告警 */
    var al = (D.alerts || []).filter(function (x) { return x.slug === slug; }).slice(-6).reverse();
    if (al.length) {
      h += '<div class="sub-h">最近事件</div><div class="small">';
      al.forEach(function (x) {
        h += '<div class="row" style="gap:8px;padding:3px 0"><span class="mono xsmall dim" style="width:86px">' +
          esc(shortTime(x.ts)) + "</span><span class=\"fg2\">" + esc(x.lines.join(" · ").slice(0, 90)) + "</span></div>";
      });
      h += "</div>";
    }

    /* IP 与归属：一个机场解析出的全部地址（含 GeoDNS 海外视角补充） */
    var iprows = a.ips || [];
    if (iprows.length) {
      var altN = 0;
      iprows.forEach(function (r) { if (r[6]) altN++; });
      h += '<div class="sub-h">IP 与归属（' + iprows.length + " 个地址" +
        (altN ? '，其中 ' + altN + " 个只在海外 DNS 可见" : "") + "，按承载节点数排序）</div>";
      h += '<div class="nodewrap"><table class="tbl compact nodetbl"><thead><tr>' +
        '<th>解析 IP</th><th>netname</th><th>机构 / 运营方</th><th>国家/地区</th><th>ASN</th>' +
        '<th class="num">承载节点</th><th>线路视角</th></tr></thead><tbody>';
      iprows.forEach(function (r) {
        var alt = r[6];
        h += "<tr><td class=\"mono xsmall\">" + esc(r[0]) + "</td>" +
          '<td class="mono xsmall dim">' + esc(r[1] || "—") + "</td>" +
          '<td class="xsmall">' + esc(r[2] || "—") + "</td>" +
          '<td class="xsmall dim">' + esc(r[3] || "—") + "</td>" +
          '<td class="mono xxsmall dim">' + esc(r[5] || "—") + "</td>" +
          '<td class="num mono xsmall">' + num(r[4] || 0) + "</td>" +
          "<td>" + (alt ? '<span class="ipalt">海外独有</span>' : '<span class="xsmall dim">国内可见</span>') + "</td></tr>";
      });
      h += "</tbody></table></div>" +
        '<div class="xsmall dim" style="margin:4px 0 10px">' +
        "同一个域名问不同 DNS 会得到不同 A 记录（GeoDNS 分线）：国内 DNS 给一组国内落地，" +
        "「海外独有」那几条只有问 1.1.1.1 才出现。<b>这些 IP 全是入口</b>——你连它，它再转到落地，" +
        "出口 IP 订阅里不会给（见 docs/20 实测：7 条样本 0 条入口=出口）。" +
        "本表只讲解析与归属，<b>不代表这些 IP 此刻能不能连</b>；连通性看下方节点的探活（按机场抽 5 个节点测 TCP）。</div>";
    }

    /* 节点全量 */
    var rows = a.node_rows || [];
    if (rows.length) {
      var pc = {};
      rows.forEach(function (r) { pc[r[1]] = (pc[r[1]] || 0) + 1; });
      h += '<div class="sub-h">节点（全部 ' + rows.length + ' 条）</div>';
      h += '<div class="nodewrap"><table class="tbl compact nodetbl"><thead><tr>' +
        '<th class="nm">名称</th><th>协议</th><th>地址</th><th>解析 IP</th><th>归属</th></tr></thead><tbody>';
      rows.forEach(function (r) {
        var own = r[6] || r[5] || "—";
        var hot2 = own.indexOf("华为") === 0 ? ' class="hot"' : "";
        var ip = r[7] || "";
        var nip = r[8] || 0;
        var ipCell = ip
          ? esc(ip) + (nip > 1 ? ' <span class="ipmore">+' + (nip - 1) + "</span>" : "")
          : "未解析";
        h += '<tr><td class="nm xsmall">' + esc(r[0] || "—") + '</td><td class="xsmall nowrap"><i class="dotc" style="background:' +
          protoColor(r[1]) + ';margin-right:5px"></i>' + esc(r[1]) + '</td><td class="mono xsmall dim">' + esc(r[2]) + ":" + (r[3] || "") +
          '</td><td class="mono xsmall' + (ip ? "" : " dim") + '">' + ipCell + '</td><td class="xsmall dim"' + hot2 + ">" + esc(own) + "</td></tr>";
      });
      h += "</tbody></table></div>";
    } else {
      h += '<div class="sub-h">节点</div><div class="small dim">这家当前没有可用快照节点。</div>';
    }


    $("#drBody").innerHTML = h;
    $("#dr").classList.add("on");
    $("#bd").classList.add("on");

    loadAirportInfo(slug);
    $("#apFetch").addEventListener("click", function () { fetchNodes(slug); });
    [["apFileRaw", "raw"], ["apFileSnap", "snap"], ["apFileYaml", "yaml"]].forEach(function (p) {
      var el = $("#" + p[0]);
      if (el) el.addEventListener("click", function () { viewFile(slug, p[1]); });
    });
  }

  /* 看打码后的原始文件：原文 / 快照 / 导出配置 */
  function viewFile(slug, kind) {
    openModal("读取中…", "正在取文件…");
    fetch("api/file/" + encodeURIComponent(slug) + "?kind=" + kind, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) { openModal("取不到这个文件", j.error || "未知原因"); return; }
        openModal(j.title || kind, j.text || "");
      })
      .catch(function (e) { openModal("取不到这个文件", String(e)); });
  }

  /* ------------------------------------------------------ 本地预览后端 */
  function infraText(a) {
    var arr = a.infra || [];
    if (!arr.length) return "—";
    var tot = 0;
    arr.forEach(function (x) { tot += x[1]; });
    if (!tot) return "—";
    var out = [];
    for (var i = 0; i < arr.length; i++) {
      var nm = arr[i][0], n = arr[i][1];
      var hot = nm.indexOf("华为") === 0 ? ' class="hot"' : "";
      out.push("<span" + hot + ">" + esc(nm) + " " + Math.round(n / tot * 100) + "%</span>");
    }
    return out.join(" · ");
  }

var API = { ok: false, reason: "" };

  function probeApi() {
    return fetch("api/status", { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        API.ok = true;
        return r.json().then(function (j) {
          API.wd = j.watchdog || null;
          API.proxy = j.proxy !== false;
          API.round = j;
          /* 定时轮收尾后 last_run.ended_at 会变：数据自己刷新，不用手动 F5 */
          var sig = String(j.started_at || "") + "|" + String(j.ended_at || "") + "|" + String(j.nodes_total || "");
          if (API.sig && API.sig !== sig) {
            reloadData().then(function (ok) {
              if (ok && typeof toast === "function") {
                toast("检测到新一轮跑完（" + (j.nodes_total == null ? "—" : j.nodes_total) + " 个节点），已自动刷新");
              }
            });
          }
          API.sig = sig;
          if (S.view === "run" && RENDER.run) RENDER.run();
        }).catch(function () {});
      })
      .catch(function () {
        API.ok = false;
        API.reason = "本地预览服务未启动（用 python tools/panel_preview_server.py 打开本页才有）";
      });
  }

  function apiGet(path) {
    return fetch(path, { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }

  function apRow(k, v) {
    return '<div class="aprow"><div class="apk">' + esc(k) + '</div><div class="apv">' + v + "</div></div>";
  }

  function loadAirportInfo(slug) {
    var box = $("#apInfo");
    if (!box) return;
    if (!API.ok) {
      box.innerHTML = apRow("面板", "—") +
        apRow("订阅", "—") +
        apRow("说明", '<span class="dim">' + esc(API.reason) + "</span>");
      var btn = $("#apFetch");
      if (btn) { btn.disabled = true; btn.title = API.reason; }
      $("#apFetchMsg").textContent = "需先启动本地预览服务";
      return;
    }
    apiGet("api/airport/" + encodeURIComponent(slug)).then(function (d) {
      var panel = d.panel
        ? '<a class="link mono" href="' + esc(d.panel) + '" target="_blank" rel="noreferrer">' +
          esc(d.panel_host || d.panel) + "</a>"
        : '<span class="dim">未登记</span>';

      var pr = d.sub_probe || {};
      var prTag = "";
      if (d.sub_present && pr.at) {
        var st = pr.status, note = pr.note || "";
        var good = pr.ok;
        prTag = good
          ? ' <span class="pill ok" title="' + esc(pr.ua || "") + ' 实测 ' + esc(pr.at) + '">订阅可用 ' + num(pr.bytes) + "B</span>"
          : ' <span class="pill r" title="实测 ' + esc(pr.at) + '（' + esc(pr.via || "-") + '）">' +
            esc(st ? "HTTP " + st : (note || "不可用")) + "</span>";
      }
      var localNote = (d.via === "本地抓包" || d.via === "本地配置解包")
        ? ' <span class="xsmall dim">节点实际来自「' + esc(d.via) + '」，与这条链接无关</span>' : "";
      var sub = d.sub_present
        ? '<span class="mono" id="apSubVal">' + esc(d.sub_masked) + "</span>" + prTag +
          ' <button class="btn mini" id="apSubShow">显示</button>' +
          ' <button class="btn mini" id="apSubCopy">复制</button>' +
          ' <button class="btn mini" id="apSubEdit">修改</button>' + localNote
        : '<span class="dim">无订阅地址（客户端型，靠 core 扫描）</span>' +
          ' <button class="btn mini" id="apSubEdit">填写</button>';

      var cl = d.client
        ? esc(d.client) + (d.client_local ? " v" + esc(d.client_local) : "") +
          (d.client_latest && d.client_latest !== d.client_local ? " → 新版 " + esc(d.client_latest) : "")
        : '<span class="dim">—</span>';

      box.innerHTML = apRow("面板", panel) +
        apRow("订阅", sub) +
        apRow("类型", esc(d.type === "client" ? "客户端型" : "订阅型") + (d.core ? " · " + esc(d.core) : "")) +
        apRow("客户端", cl) +
        apRow("后端", esc(d.state || "—") + " · 可用节点 " + num(d.nodes || 0) + " / 可导出 " + num(d.exported || 0) +
              (d.frag ? " <span class=\"dim\">（另有 " + num(d.frag) + " 条无协议碎片，导不进配置）</span>" : "")) +
        '<div class="subedit" id="apSubEditBox" style="display:none">' +
        '<div class="sub-h" style="margin-top:10px">改订阅地址</div>' +
        '<input class="inp" id="apSubInput" spellcheck="false" autocomplete="off" ' +
        'placeholder="粘贴新的订阅链接（https://…）">' +
        '<div class="row" style="gap:8px;align-items:center;margin-top:8px">' +
        '<button class="btn primary mini" id="apSubSave">保存</button>' +
        '<button class="btn mini" id="apSubCancel">取消</button>' +
        '<span class="small" id="apSubMsg"></span></div>' +
        '<div class="xsmall dim" style="margin-top:6px;line-height:1.6">' +
        '保存会直接写回 <span class="mono">credentials.yaml</span>（先备份到 data/backup/），' +
        '只改这一家的 sub_url，不动其它字段。改完点上面的「获取节点」才会用新链接拉节点。</div>' +
        "</div>";

      var show = $("#apSubShow");
      if (show) {
        show.addEventListener("click", function () {
          if (show.dataset.on === "1") {
            $("#apSubVal").textContent = d.sub_masked;
            show.dataset.on = "0";
            show.textContent = "显示";
            return;
          }
          apiGet("api/airport/" + encodeURIComponent(slug) + "?reveal=1").then(function (full) {
            $("#apSubVal").textContent = full.sub_full || d.sub_masked;
            show.dataset.on = "1";
            show.textContent = "隐藏";
          }).catch(function () { $("#apFetchMsg").textContent = "取完整链接失败"; });
        });
      }
      var cp = $("#apSubCopy");
      if (cp) {
        cp.addEventListener("click", function () {
          cp.disabled = true;
          cp.textContent = "复制中…";
          apiGet("api/airport/" + encodeURIComponent(slug) + "?reveal=1").then(function (full) {
            var url = (full && full.sub_full) || "";
            if (!url) throw new Error("没有订阅地址");
            copyText(url, function (how) {
              cp.disabled = false;
              if (how === "ok") {
                cp.textContent = "已复制";
                setTimeout(function () { cp.textContent = "复制"; }, 1400);
              } else {
                selectSubText(url);
                cp.textContent = "已选中，Ctrl+C";
                setTimeout(function () { cp.textContent = "复制"; }, 6000);
                var msg = $("#apFetchMsg");
                if (msg) msg.textContent = "浏览器不允许直接写剪贴板，链接已全选——按 Ctrl+C 即可。";
              }
            });
          }).catch(function (e) {
            cp.disabled = false;
            cp.textContent = "复制失败";
            var msg = $("#apFetchMsg");
            if (msg) msg.textContent = "读取订阅地址失败：" + (e && e.message || "未知错误");
            setTimeout(function () { cp.textContent = "复制"; }, 2000);
          });
        });
      }
      var lo = $("#apLastOk");
      if (lo && d.last_ok) lo.textContent = relTime(d.last_ok) + "（" + d.last_ok + "）";
      bindSubEditor(slug);
    }).catch(function (e) {
      box.innerHTML = apRow("说明", '<span class="dim">读取失败：' + esc(e.message) + "</span>");
    });
  }

  /* 改订阅地址：POST api/sub -> 写回 credentials.yaml（后端会先备份并回读校验） */
  function bindSubEditor(slug) {
    var btn = $("#apSubEdit"), boxEl = $("#apSubEditBox"), inp = $("#apSubInput");
    if (!btn || !boxEl) return;
    btn.dataset.orig = btn.textContent;
    btn.addEventListener("click", function () {
      var on = boxEl.style.display !== "none";
      boxEl.style.display = on ? "none" : "block";
      btn.textContent = on ? btn.dataset.orig : "收起";
      if (!on) {
        inp.value = "";
        inp.placeholder = "粘贴新的订阅链接（https://…）；留空保存=清空这家订阅";
        inp.focus();
        $("#apSubMsg").textContent = "";
      }
    });
    $("#apSubCancel").addEventListener("click", function () {
      boxEl.style.display = "none";
      btn.textContent = btn.dataset.orig || "修改";
    });
    $("#apSubSave").addEventListener("click", function () {
      var v = (inp.value || "").trim();
      var msg = $("#apSubMsg");
      if (!v && !confirm("留空保存会把 " + slug + " 的订阅地址清空，确定？")) return;
      var save = $("#apSubSave");
      save.disabled = true;
      msg.className = "small dim";
      msg.textContent = "保存中…";
      fetch("api/sub", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: slug, sub_url: v })
      }).then(function (r) {
        return r.json().then(function (j) { return { code: r.status, j: j }; });
      }).then(function (res) {
        save.disabled = false;
        if (!res.j || !res.j.ok) {
          msg.className = "small";
          msg.style.color = "var(--red)";
          msg.textContent = "保存失败：" + ((res.j && res.j.error) || ("HTTP " + res.code));
          return;
        }
        msg.className = "small okc";
        msg.style.color = "";
        msg.textContent = "已保存" + (res.j.unchanged ? "（与原来相同）" : "") +
          " · 备份 " + String(res.j.backup || "").split("/").pop() +
          " · 第 " + (res.j.line || "?") + " 行";
        var val = $("#apSubVal");
        if (res.j.present && val) {
          /* 本来就有订阅：就地改显示，不重绘（否则提示会被刷掉） */
          val.textContent = res.j.masked || "";
          setTimeout(function () {
            boxEl.style.display = "none";
            btn.textContent = btn.dataset.orig || "修改";
          }, 1100);
        } else {
          /* 有↔无 切换：需要重绘整块，按钮也要换 */
          setTimeout(function () { loadAirportInfo(slug); }, 1300);
        }
      }).catch(function (e) {
        save.disabled = false;
        msg.className = "small";
        msg.style.color = "var(--red)";
        msg.textContent = "保存失败：" + ((e && e.message) || "网络错误");
      });
    });
  }

  /* 复制到剪贴板：沙箱 iframe 里 navigator.clipboard 常被拒（NotAllowedError），
     逐级降级 -> execCommand("copy") -> 选中文本让用户按 Ctrl+C。 */
  function copyText(text, done) {
    function legacy() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.cssText = "position:fixed;top:0;left:-9999px;opacity:0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        ta.setSelectionRange(0, text.length);
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        return ok;
      } catch (e) { return false; }
    }
    try { window.focus(); } catch (e) {}
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { done("ok"); },
        function () { done(legacy() ? "ok" : "manual"); }
      );
    } else {
      done(legacy() ? "ok" : "manual");
    }
  }

  /* 复制失败时把全文露出并整段选中，用户按 Ctrl+C 即可 */
  function selectSubText(text) {
    var el = $("#apSubVal");
    if (!el) return;
    el.textContent = text;
    try {
      var r = document.createRange();
      r.selectNodeContents(el);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
    } catch (e) {}
  }

  var fetchTimers = {};

  function fetchNodes(slug) {
    var btn = $("#apFetch");
    var msg = $("#apFetchMsg");
    var log = $("#apLog");
    if (!API.ok) { msg.textContent = API.reason; return; }

    // 代理没开：订阅站点基本都会超时，先提醒一次；再点就放行
    if (API.proxy === false && !API.proxyWarned) {
      API.proxyWarned = true;
      msg.innerHTML = '<span style="color:var(--amber)">代理没开（[::1]:7890）</span>' +
        '<span class="dim small"> —— 订阅站点大多在墙外，这次大概率会超时。' +
        '先打开代理客户端，再点一次；或直接再点一次按直连试。</span>';
      return;
    }

    btn.disabled = true;
    msg.innerHTML = '<span class="spin"></span>正在开始…';
    log.style.display = "block";
    log.textContent = "";

    fetch("api/fetch/" + encodeURIComponent(slug), { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (!res.ok) throw new Error(res.error || "启动失败");
        pollFetch(slug);
      })
      .catch(function (e) {
        btn.disabled = false;
        msg.textContent = "";
        log.textContent = "无法开始：" + e.message;
        log.className = "logbox";
      });
  }

  function pollFetch(slug) {
    var log = $("#apLog");
    var msg = $("#apFetchMsg");
    var btn = $("#apFetch");
    apiGet("api/fetch/" + encodeURIComponent(slug)).then(function (j) {
      if (j.tail && j.tail.length) log.textContent = j.tail.join("\n");
      log.scrollTop = log.scrollHeight;

      if (j.state === "running") {
        var m = (j.mode || "");
        if (j.elevated) {
          msg.innerHTML = '<span class="spin"></span>已请求管理员权限 · 请在弹出的 UAC 窗口点「是」';
        } else if (m.indexOf("scan-memory") === 0) {
          msg.innerHTML = '<span class="spin"></span>正在扫描客户端内存（' + m.replace("scan-memory · ", "") + '）…';
        } else {
          msg.innerHTML = '<span class="spin"></span>正在拉取订阅…';
        }
        clearTimeout(fetchTimers[slug]);
        fetchTimers[slug] = setTimeout(function () { pollFetch(slug); }, 1200);
        return;
      }
      btn.disabled = false;
      if (j.state === "done") {
        if (j.regen === "ok") {
          msg.innerHTML = '<span style="color:var(--green)">完成</span> · 正在更新卡片…';
          reloadData().then(function (ok) {
            if (ok) {
              var a2 = bySlug[slug];
              var okTxt = '<span style="color:var(--green)">完成</span> · 已刷新' +
                (a2 ? "：现在 " + stName(a2.state) + " · " + num(a2.nodes) + " 个节点" : "");
              /* 先重绘抽屉（会重建 msg 元素），再写入提示，否则提示被冲掉 */
              if ($("#dr").classList.contains("on")) openDrawer(slug);
              var m2 = $("#apFetchMsg");
              if (m2) m2.innerHTML = okTxt;
            } else {
              msg.innerHTML = '<span style="color:var(--green)">完成</span> · 数据已重生成，' +
                '<a href="javascript:void 0" id="apReload" style="color:var(--blue)">点这里刷新</a>看最新卡片';
              var rl = $("#apReload");
              if (rl) rl.onclick = function () { location.reload(); };
            }
          });
        } else if (j.regen === "running") {
          msg.innerHTML = '<span style="color:var(--green)">完成</span> · 正在重新生成本页数据…';
          clearTimeout(fetchTimers[slug]);
          fetchTimers[slug] = setTimeout(function () { pollFetch(slug); }, 1500);
          log.className = "logbox";
          loadAirportInfo(slug);
          return;
        } else {
          msg.innerHTML = '<span style="color:var(--green)">完成</span> · 快照已更新（本页数据未重生成，刷新可能仍是旧值）';
        }
        log.className = "logbox";
        loadAirportInfo(slug);
      } else if (j.state === "failed") {
        msg.innerHTML = '<span style="color:var(--red)">失败</span> · 退出码 ' + (j.exit == null ? "?" : j.exit);
        log.className = "logbox bad";
      } else {
        msg.textContent = "";
      }
    }).catch(function () {
      clearTimeout(fetchTimers[slug]);
      btn.disabled = false;
      msg.textContent = "查询任务状态失败";
    });
  }

  function closeDrawer() {
    $("#dr").classList.remove("on");
    $("#bd").classList.remove("on");
  }

  /* ------------------------------------------------------------ 视图切换 */
  var VIEW_META = {
    ov: ["总览", "矩阵定位问题机场，右栏是你要做的事"],
    exp: ["到期", "套餐到期与流量使用，按剩余天数排序"],
    al: ["告警", "陈旧、波动、云厂商命中，空块已过滤"],
    hw: ["华为云关联", "会话特征聚类出的疑似云厂商实体"],
    nd: ["节点", "逐机场查看落盘节点与可导出情况"],
    lib: ["机场库", "47 家机场的注册信息、面板、客户端与信号"],
    kn: ["知识", "协议科普与机场评测档案"],
    an: ["分析", "30 天趋势、落地机房、波动与稳定性"],
    run: ["运行", "本轮采集台账与运行日志"]
  };

  /* 拉取成功后热更新：重新取 data.js、重建索引、重绘当前视图。
     这样"更新订阅 → 获取节点成功"就能当场变绿，不用手动刷新整页。 */
  function reloadData() {
    return fetch("data.js?t=" + Date.now(), { cache: "no-store" })
      .then(function (r) { return r.ok ? r.text() : ""; })
      .then(function (txt) {
        if (!txt || txt.indexOf("window.AIRMON") < 0) return false;
        try { new Function(txt)(); } catch (e) { return false; }
        if (!window.AIRMON) return false;
        D = window.AIRMON;
        T = D.totals || {};
        APTS = D.airports || [];
        bySlug = {};
        APTS.forEach(function (a) { bySlug[a.slug] = a; });
        SORTED = APTS.slice().sort(function (x, y) {
          var o = (ORDER[x.state] == null ? 9 : ORDER[x.state]) - (ORDER[y.state] == null ? 9 : ORDER[y.state]);
          return o !== 0 ? o : (y.nodes - x.nodes);
        });
        /* 各视图有 S.drawn 一次性绘制标记，数据变了必须清掉才会真正重绘 */
        S.drawn = {};
        RENDER[S.view]();
        return true;
      })
      .catch(function () { return false; });
  }

  var RENDER = {
    ov: renderOverview, exp: renderExpiry, al: renderAlerts, hw: renderHuawei,
    nd: renderNodes, lib: renderLibrary, kn: renderKnowledge, an: renderAnalysis, run: renderRun
  };

  function switchView(v) {
    if (!VIEW_META[v]) return;
    S.view = v;
    $$(".nav-item").forEach(function (b) {
      var on = b.getAttribute("data-view") === v;
      b.classList.toggle("on", on);
      if (on) moveIndicator(b);
    });
    $$(".view").forEach(function (sec) {
      sec.classList.toggle("on", sec.getAttribute("data-v") === v);
    });
    if (location.hash !== "#" + v) {
      try { history.replaceState(null, "", "#" + v); } catch (e) {}
    }
    $("#vTitle").textContent = VIEW_META[v][0];
    $("#vSub").textContent = VIEW_META[v][1];
    RENDER[v]();
    $("#views").scrollTop = 0;
  }

  function moveIndicator(btn) {
    var ind = $("#navInd");
    if (!ind) return;
    ind.style.height = btn.offsetHeight + "px";
    ind.style.transform = "translateY(" + btn.offsetTop + "px)";
  }

  /* ------------------------------------------------------------ 初始化 */
  function init() {
    initModal();
    probeApi();
    setInterval(probeApi, 60000);  /* 定时轮 6h 一次，但执行中状态/看门狗要能看到变化 */
    $("#brandSub").textContent = "本轮 " + (D.meta.base || "—");
    $("#footBase").textContent = D.meta.base || "—";
    $("#footBuilt").textContent = D.meta.built || "—";

    var r = D.meta.round || {};
    var running = D.meta.running || r.status === "running";
    $("#roundDot").className = "dot " + (running ? "b live" : r.status === "ok" ? "ok" : "d");
    $("#roundText").textContent = running
      ? "本轮采集中 · " + (r.step || "")
      : (r.status === "ok" ? "上轮 ok · " + shortTime(r.ended_at) : "上轮 " + (r.status || "—"));

    var m = D.meta.round || {};
    $("#mRound").textContent = (m.status || "—") + (m.duration_s ? " · " + (m.duration_s / 60).toFixed(0) + " 分钟" : "");
    $("#mNodes").textContent = num(T.nodes);
    $("#mExp").textContent = num(T.exported);

    /* 导航计数 */
    var K = {
      ov: "",
      exp: (T.expired || 0) + " 过期",
      al: (D.alerts || []).length + "",
      hw: (T.hw || 0) + "",
      nd: num(T.nodes),
      lib: APTS.length + "",
      kn: (D.knowledge || []).length + "",
      an: (D.meta.days || 30) + "d",
      run: "1/5"
    };
    $$("[data-k]").forEach(function (n) { n.textContent = K[n.getAttribute("data-k")] || ""; });

    /* 导航 */
    $$(".nav-item").forEach(function (b) {
      b.addEventListener("click", function () { switchView(b.getAttribute("data-view")); });
    });

    /* 搜索 */
    var qEl = $("#q");
    var timer = null;
    qEl.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        S.q = qEl.value.trim();
        RENDER[S.view]();
      }, 160);
    });

    /* 待办按钮 → 右栏 */
    $("#btnAct").addEventListener("click", function () {
      var rail = $(".rail");
      rail.scrollIntoView({ behavior: "smooth", block: "nearest" });
      rail.animate([{ opacity: 0.4 }, { opacity: 1 }], { duration: 300, easing: "ease-out" });
    });

    /* 抽屉关闭 */
    $("#drX").addEventListener("click", closeDrawer);
    $("#bd").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeDrawer();
      if (e.key >= "1" && e.key <= "9" && !/input|textarea/i.test(document.activeElement.tagName)) {
        var order = ["ov", "exp", "al", "hw", "nd", "lib", "kn", "an", "run"];
        switchView(order[+e.key - 1]);
      }
    });

    renderRail();

    /* 深链：#an 之类直接落到对应视图 */
    var hashView = (location.hash || "").replace("#", "");
    switchView(VIEW_META[hashView] ? hashView : "ov");
    window.addEventListener("hashchange", function () {
      var v = (location.hash || "").replace("#", "");
      if (VIEW_META[v] && v !== S.view) switchView(v);
    });
    requestAnimationFrame(function () {
      var on = $(".nav-item.on");
      if (on) moveIndicator(on);
    });
    window.addEventListener("resize", function () {
      var on = $(".nav-item.on");
      if (on) moveIndicator(on);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
