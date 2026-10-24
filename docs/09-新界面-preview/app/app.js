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
  var S = { view: "ov", q: "", al: "all", lib: "all", kn: "all", nd: null, ndProto: "all", density: "m", drawn: {} };

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
      '<span class="n">' + num(APTS.length) + " 家 · 按状态排序</span>" +
      '<span class="sp"></span>' +
      '<div class="row small dim" style="gap:12px">' +
      '<span class="row" style="gap:5px">' + dot("ok") + "可用 " + T.ok + "</span>" +
      '<span class="row" style="gap:5px">' + dot("b") + "异常 " + T.b + "</span>" +
      '<span class="row" style="gap:5px">' + dot("c") + "仅客户端 " + T.c + "</span>" +
      '<span class="row" style="gap:5px">' + dot("d") + "断流 " + T.d + "</span>" +
      '<span class="row" style="gap:5px"><i class="cl inline">客</i>只能用客户端获取</span>' +
      "</div>" +
      '<div class="dseg" role="group" aria-label="卡片尺寸">' +
      ["s", "m", "l"].map(function (k) {
        var lbl = { s: "小", m: "中", l: "大" }[k];
        return '<button class="dseg-b' + (S.density === k ? " on" : "") + '" data-d="' + k + '">' + lbl + "</button>";
      }).join("") +
      "</div></div>";
    h += '<div class="sec-b"><div class="matrix" id="mx" data-d="' + S.density + '">';
    SORTED.forEach(function (a) {
      var cls = stCls(a.state);
      var clOnly = a.type === "client" && !a.has_sub;
      var expired = a.days != null && a.days < 0;
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
            (expired ? '<i class="xd" aria-label="套餐已到期">到期</i>' : "") + "</span>" +
          '<span class="ex' + (a.exported ? "" : (expired ? " bad" : " dim")) + '">' + exTxt + "</span>" +
        "</span>" +
        "</button>";
    });
    h += "</div></div></div>";

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
        '<td style="width:74px">' + pill("pill " + (KIND_CLS[x.kind] || ""), KIND_NAME[x.kind] || x.kind) + "</td>" +
        '<td class="xsmall">' + esc(x.lines.join(" · ").slice(0, 180)) + "</td></tr>";
    });
    h += "</tbody></table></div></div></div>";

    h += '<div class="mt14 hint">陈旧 = 快照超过 6 小时未更新；波动 = 本轮相对上一份快照的大幅增删；华为 = 命中云厂商特征。空块已在生成阶段丢弃。</div>';
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
    var hw = D.hw || {};
    var sum = hw.summary || {};
    var ents = hw.entities || [];

    var cards = [
      { lb: "关联实体", vl: sum.entities_total || 0, ft: "会话特征聚类后" },
      { lb: "强关联", vl: sum.strong || 0, ft: "level=strong" },
      { lb: "中等关联", vl: sum.mid || 0, ft: "level=mid" },
      { lb: "输入会话", vl: hw.input_sessions != null ? hw.input_sessions : (hw.lib || {}).ip_dom_entries || 0, ft: "机场库条目 " + num((hw.lib || {}).ip_dom_entries || 0) }
    ];

    var h = '<div class="hw-cards">';
    cards.forEach(function (c, i) {
      h += '<div class="hw-c"><div class="lb">' + esc(c.lb) + '</div><div class="vl" data-hw="' + i + '">0</div><div class="ft">' + esc(c.ft) + "</div></div>";
    });
    h += "</div>";

    h += '<div class="sec"><div class="sec-h"><h2>判定维度</h2>' +
      '<span class="n">' + esc(hw.generated_at || "—") + "</span></div><div class=\"sec-b\"><div class=\"judges\">";
    String(hw.judges || "").split(" ").forEach(function (j) {
      if (j) h += '<span class="pill">' + esc(j) + "</span>";
    });
    h += "</div><div class=\"mt8 hint\">" + esc(hw.scope || "") + "</div></div></div>";

    h += '<div class="sec mt14"><div class="sec-h"><h2>关联实体</h2>' +
      '<span class="n">' + num(ents.length) + " 条</span></div>" +
      '<div class="sec-b tight"><div class="tbl-wrap"><table class="tbl compact"><thead><tr>' +
      '<th>目标</th><th class="num">会话</th><th class="num">流量</th><th class="num">评分</th><th>等级</th><th>命中机场</th><th>依据</th>' +
      "</tr></thead><tbody>";
    if (!ents.length) {
      h += '<tr><td colspan="7" class="dim">本轮没有关联实体。华为云检测依赖会话特征，需要长连接样本才会命中。</td></tr>';
    }
    ents.forEach(function (e) {
      h += "<tr>" +
        '<td class="nm mono">' + esc(e.dst || "—") + "</td>" +
        '<td class="num">' + num(e.sessions || 0) + "</td>" +
        '<td class="num">' + esc(bytesMB(e.bytes)) + "</td>" +
        '<td class="num">' + num(e.score || 0) + "</td>" +
        '<td>' + pill(e.level === "strong" ? "pill d" : "pill b", esc(e.level || "—")) + "</td>" +
        '<td class="xsmall">' + esc((e.hits || []).join("、") || "—") + "</td>" +
        '<td class="xsmall dim">' + esc((e.why || []).join(" · ") || "—") + "</td></tr>";
    });
    h += "</tbody></table></div></div></div>";

    var lib = hw.lib || {};
    h += '<div class="grid2 mt14">' +
      '<div class="sec"><div class="sec-h"><h2>机场库覆盖</h2><span class="n">拿什么去比对</span></div><div class="sec-b">' +
      '<dl class="kv">' +
      "<dt>覆盖机场</dt><dd>" + num(lib.airports || 0) + " 家</dd>" +
      "<dt>IP·域条目</dt><dd>" + num(lib.ip_dom_entries || 0) + " 条</dd>" +
      "<dt>域名条目</dt><dd>" + num(lib.domains || 0) + " 条（CNAME 维尚空）</dd>" +
      "<dt>输入会话</dt><dd>" + (hw.input_sessions != null ? hw.input_sessions : "—") + " 段</dd>" +
      "</dl><div class=\"mt8 hint\">库由快照 server 字段与 RDAP 归属汇总而来；域名维为空时，只能靠 IP 匹配，漏报会偏多。</div></div></div>" +
      '<div class="sec"><div class="sec-h"><h2>六个判定维度</h2><span class="n">命中越多分越高</span></div><div class="sec-b">' +
      '<div class="small fg2" style="line-height:2">' +
      "<div><b class=\"mono\">J1</b> 长连接：单条 TCP 持续 30 分钟以上</div>" +
      "<div><b class=\"mono\">J2</b> 高位端口：非 80/443 的高位端口出网</div>" +
      "<div><b class=\"mono\">J3</b> 扇入：同一目标被多个源地址连接</div>" +
      "<div><b class=\"mono\">J4</b> 字节比：上传远大于下载（隧道特征）</div>" +
      "<div><b class=\"mono\">J5</b> 机场 IP：目标命中机场节点 IP 库</div>" +
      "<div><b class=\"mono\">J6</b> 机场域名：目标命中机场域名库</div>" +
      "</div><div class=\"mt8 hint\">本轮只有 " + num(sum.entities_total || 0) + " 条实体：样本里长连接少，命中就少，这属于检出力问题而不是「没有」。</div></div></div>" +
      "</div>";

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
      "</div></div>";

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
    h += "</div></div></div>";

    v.innerHTML = h;
    $$("#libChips .chip", v).forEach(function (b) {
      b.addEventListener("click", function () { S.lib = b.getAttribute("data-lib"); renderLibrary(); });
    });
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

    var h = '<div class="kpis" style="grid-template-columns:repeat(5,minmax(0,1fr))">' +
      '<div class="kpi ' + (r.status === "ok" ? "ok" : "b") + '"><div class="lb">本轮状态</div><div class="vl" style="font-size:22px">' + esc(r.status || "—") + '</div><div class="ft">' + esc(r.step || "") + "</div></div>" +
      '<div class="kpi"><div class="lb">耗时</div><div class="vl" style="font-size:22px">' + esc(dur) + '</div><div class="ft">' + esc(shortTime(r.started_at)) + " → " + esc(shortTime(r.ended_at)) + "</div></div>" +
      '<div class="kpi ok"><div class="lb">拉取成功</div><div class="vl" style="font-size:22px">' + (ok == null ? "—" : num(ok)) + '</div><div class="ft">家机场</div></div>' +
      '<div class="kpi d"><div class="lb">拉取失败</div><div class="vl" style="font-size:22px">' + (fail == null ? "—" : num(fail)) + '</div><div class="ft">含网络抖动</div></div>' +
      '<div class="kpi t"><div class="lb">采集节点</div><div class="vl" style="font-size:22px">' + (r.nodes_total == null ? num(T.nodes) : num(r.nodes_total)) + '</div><div class="ft">华为命中 ' + (r.hw_findings == null ? "—" : r.hw_findings) + "</div></div>" +
      "</div>";

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

    v.innerHTML = h;
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
      ["快照节点", num(a.nodes) + " 条 · 可导出 " + num(a.exported)],
      ["获取方式", esc(a.via || "—")],
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

    /* 节点全量 */
    var rows = a.node_rows || [];
    if (rows.length) {
      var pc = {};
      rows.forEach(function (r) { pc[r[1]] = (pc[r[1]] || 0) + 1; });
      h += '<div class="sub-h">节点（全部 ' + rows.length + ' 条）</div>';
      h += '<div class="nodewrap"><table class="tbl compact nodetbl"><thead><tr>' +
        '<th class="nm">名称</th><th>协议</th><th>地址</th><th>归属</th></tr></thead><tbody>';
      rows.forEach(function (r) {
        var own = r[6] || r[5] || "—";
        var hot2 = own.indexOf("华为") === 0 ? ' class="hot"' : "";
        h += '<tr><td class="nm xsmall">' + esc(r[0] || "—") + '</td><td class="xsmall nowrap"><i class="dotc" style="background:' +
          protoColor(r[1]) + ';margin-right:5px"></i>' + esc(r[1]) + '</td><td class="mono xsmall dim">' + esc(r[2]) + ":" + (r[3] || "") + '</td><td class="xsmall dim"' + hot2 + ">" + esc(own) + "</td></tr>";
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

      var sub = d.sub_present
        ? '<span class="mono" id="apSubVal">' + esc(d.sub_masked) + "</span>" +
          ' <button class="btn mini" id="apSubShow">显示</button>' +
          ' <button class="btn mini" id="apSubCopy">复制</button>' +
          ' <button class="btn mini" id="apSubEdit">修改</button>'
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
        apRow("后端", esc(d.state || "—") + " · 快照 " + num(d.nodes || 0) + " / 可导出 " + num(d.exported || 0)) +
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

    btn.disabled = true;
    msg.innerHTML = '<span class="spin"></span>正在拉取…';
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
    probeApi();
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
