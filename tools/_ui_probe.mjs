// 面板布局机械体检：跑 headless Chrome，逐视图采集几何与文本溢出
// 用法：node tools/_ui_probe.mjs docs/09-新界面-preview/app/index.html
import puppeteer from "file:///C:/Users/minions/.dsh/profiles/desktop/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js";
import path from "node:path";
import { pathToFileURL } from "node:url";

const file = process.argv[2];
const views = ["ov", "exp", "al", "hw", "nd", "lib", "kn", "an", "run"];
const browser = await puppeteer.launch({
  executablePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  headless: "new",
  args: ["--no-sandbox", "--disable-gpu", "--font-render-hinting=none"],
});
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });

const errs = [];
page.on("console", (m) => { if (m.type() === "error") errs.push(m.text()); });
page.on("pageerror", (e) => errs.push("PAGEERROR " + e.message));

const url = pathToFileURL(path.resolve(file)).href;
const out = [];

for (const v of views) {
  await page.goto(url + "#" + v, { waitUntil: "networkidle0" });
  await new Promise((r) => setTimeout(r, 260));
  const info = await page.evaluate(() => {
    const sec = document.querySelector('.view.on');
    const r = (el) => el ? el.getBoundingClientRect() : null;
    const box = sec.getBoundingClientRect();
    const docEl = document.documentElement;

    // 文本溢出容器（横向）
    const clipped = [];
    sec.querySelectorAll('*').forEach((el) => {
      if (el.children.length > 0 && getComputedStyle(el).overflow === 'visible') return;
      const t = (el.textContent || '').trim();
      if (!t || t.length < 3) return;
      if (el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0) {
        clipped.push({ cls: (el.className || '').toString().slice(0, 40), t: t.slice(0, 40), sw: el.scrollWidth, cw: el.clientWidth });
      }
    });

    // 横向越界元素
    const over = [];
    sec.querySelectorAll('*').forEach((el) => {
      const b = el.getBoundingClientRect();
      if (b.width && b.right > docEl.clientWidth + 1) over.push({ cls: (el.className||'').toString().slice(0,40), right: Math.round(b.right) });
    });

    // 内容高度与底部空白
    let bottom = 0;
    sec.querySelectorAll('*').forEach((el) => {
      const b = el.getBoundingClientRect();
      if (b.height < 3) return;
      const st = getComputedStyle(el);
      if (st.position === 'fixed' || st.display === 'none' || st.visibility === 'hidden') return;
      bottom = Math.max(bottom, b.bottom + window.scrollY);
    });

    const counts = {
      kpi: sec.querySelectorAll('.kpi').length,
      cell: sec.querySelectorAll('.cell').length,
      tblRow: sec.querySelectorAll('table.tbl tbody tr').length,
      card: sec.querySelectorAll('.card').length,
      kn: sec.querySelectorAll('.kn').length,
      act: document.querySelectorAll('#actList .act').length,
      chip: sec.querySelectorAll('.chip').length,
    };

    const empty = [];
    sec.querySelectorAll('.sec, .kpis, .hw-cards, .cards, .kn-grid').forEach((el) => {
      if (el.getBoundingClientRect().height < 32) empty.push((el.className||'').toString().slice(0,40));
    });

    const cs = getComputedStyle(document.querySelector('.kpi .lb') || document.body);
    return {
      view: sec.dataset.v,
      viewW: Math.round(box.width),
      viewH: Math.round(box.height),
      scrollW: docEl.scrollWidth,
      clientW: docEl.clientWidth,
      contentBottom: Math.round(bottom),
      viewportH: window.innerHeight,
      counts,
      clipped: clipped.slice(0, 6),
      over: over.slice(0, 6),
      empty,
      lbColor: cs.color,
      title: document.querySelector('#vTitle').textContent,
    };
  });
  out.push(info);
}

// 对比度抽检：算出 --fg3/--fg2/--fg1 与背景的比值
await page.goto(url + "#ov", { waitUntil: "networkidle0" });
const contrast = await page.evaluate(() => {
  const lum = (rgb) => {
    const [r, g, b] = rgb.map((v) => {
      v = v / 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const parse = (s) => s.match(/\d+/g).slice(0, 3).map(Number);
  const ratio = (a, b) => {
    const l1 = lum(parse(a)), l2 = lum(parse(b));
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  };
  const bg = getComputedStyle(document.querySelector('.sec')).backgroundColor;
  const out = { bg };
  [['fg3', '.kpi .lb'], ['fg2', '.rail-meta'], ['fg1', '.cell .nm'], ['dim', '.hint']].forEach(([k, sel]) => {
    const el = document.querySelector(sel);
    if (el) out[k] = Math.round(ratio(getComputedStyle(el).color, bg) * 100) / 100;
  });
  return out;
});

console.log(JSON.stringify({ errs, views: out, contrast }, null, 1));
await browser.close();
