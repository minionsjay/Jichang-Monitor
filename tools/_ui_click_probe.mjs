// 交互断言：矩阵卡片点击是否打开抽屉；卡片尺寸是否够读；总览是否还能一屏
// 用法：node tools/_ui_click_probe.mjs [url]
import puppeteer from "file:///C:/Users/minions/.dsh/profiles/desktop/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js";

const url = process.argv[2] || "http://127.0.0.1:56990/index.html#ov";
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

await page.goto(url, { waitUntil: "networkidle0" });
await new Promise((r) => setTimeout(r, 300));

const geo = await page.evaluate(() => {
  const cells = [...document.querySelectorAll("#mx .cell")];
  const c0 = cells[0]?.getBoundingClientRect();
  const mx = document.querySelector("#mx");
  const cs = getComputedStyle(mx);
  const cols = cs.gridTemplateColumns.split(" ").length;
  const view = document.querySelector(".view.on");
  return {
    cells: cells.length,
    cellW: Math.round(c0?.width || 0),
    cellH: Math.round(c0?.height || 0),
    cols,
    density: mx.dataset.d,
    nameFont: getComputedStyle(cells[0].querySelector(".nm")).fontSize,
    cntFont: getComputedStyle(cells[0].querySelector(".ct")).fontSize,
    hasStatusWord: !!cells[0].querySelector(".st"),
    viewH: Math.round(view.getBoundingClientRect().height),
    scrollH: Math.round(view.scrollHeight),
    dseg: document.querySelectorAll(".dseg-b").length,
  };
});
console.log("几何:", JSON.stringify(geo));

// 点第 3 张卡
await page.click("#mx .cell:nth-child(3)");
await new Promise((r) => setTimeout(r, 420));
const dr = await page.evaluate(() => {
  const d = document.querySelector("#dr");
  return {
    open: d.classList.contains("on"),
    title: (document.querySelector("#drTitle")?.textContent || "").trim(),
    kv: document.querySelectorAll("#dr .kv dt").length,
    action: !!document.querySelector("#dr .small[style*='teal']"),
    rows: document.querySelectorAll("#dr .tbl tr").length,
    visibleW: Math.round(d.getBoundingClientRect().width),
  };
});
console.log("抽屉:", JSON.stringify(dr));

// 关掉，切到小尺寸再点一次
await page.click("#drX");
await new Promise((r) => setTimeout(r, 260));
await page.click('.dseg-b[data-d="s"]');
await new Promise((r) => setTimeout(r, 260));
const small = await page.evaluate(() => {
  const cells = [...document.querySelectorAll("#mx .cell")];
  const c0 = cells[0].getBoundingClientRect();
  const view = document.querySelector(".view.on");
  return {
    density: document.querySelector("#mx").dataset.d,
    cellW: Math.round(c0.width), cellH: Math.round(c0.height),
    cols: getComputedStyle(document.querySelector("#mx")).gridTemplateColumns.split(" ").length,
    viewH: Math.round(view.getBoundingClientRect().height),
    scrollH: Math.round(view.scrollHeight),
  };
});
console.log("小尺寸:", JSON.stringify(small));
await page.click("#mx .cell:nth-child(5)");
await new Promise((r) => setTimeout(r, 320));
const open2 = await page.evaluate(() => document.querySelector("#dr").classList.contains("on"));
console.log("小尺寸下点击仍打开抽屉:", open2);

// 中尺寸
await page.click("#drX");
await new Promise((r) => setTimeout(r, 200));
await page.click('.dseg-b[data-d="m"]');
await new Promise((r) => setTimeout(r, 260));
const mid = await page.evaluate(() => {
  const c0 = document.querySelector("#mx .cell").getBoundingClientRect();
  const view = document.querySelector(".view.on");
  return { cellW: Math.round(c0.width), cellH: Math.round(c0.height), scrollH: Math.round(view.scrollHeight) };
});
console.log("中尺寸:", JSON.stringify(mid));

console.log("控制台错误:", errs.length ? errs.slice(0, 4) : "无");
await browser.close();
