// Record polished UI reels with Playwright (VP8 webm). Run: node record-reels.cjs <which>
const { chromium } = require('/root/wt-transport/experiments/ux/node_modules/playwright');
const path = require('path');
const OUT = path.join(__dirname, '.webm');
const fs = require('fs');
fs.mkdirSync(OUT, { recursive: true });

const ARGS = ['--disable-features=WebRtcHideLocalIpsWithMdns'];
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// gentle "human" click on a locator by text
async function tap(page, text, hold = 700) {
  const loc = page.locator(`button:has-text("${text}")`).first();
  await loc.hover({ timeout: 2500 }).catch(() => {});
  await sleep(220);
  await loc.click({ timeout: 2500 }).catch(() => {});
  await sleep(hold);
}

async function record(name, viewport, fn) {
  const browser = await chromium.launch({ args: ARGS });
  const ctx = await browser.newContext({
    viewport,
    recordVideo: { dir: OUT, size: viewport },
    deviceScaleFactor: 1,
  });
  const page = await ctx.newPage();
  page.setDefaultTimeout(3000);
  await fn(page);
  await page.waitForTimeout(500);
  await page.close();       // finalize the page video
  await ctx.close();        // flushes the video

  await browser.close();
  // rename the produced webm
  const files = fs.readdirSync(OUT).filter(f => f.endsWith('.webm'));
  // newest
  let newest = null, mt = 0;
  for (const f of files) { const st = fs.statSync(path.join(OUT, f)); if (st.mtimeMs > mt && !f.startsWith(name)) { mt = st.mtimeMs; newest = f; } }
  if (newest) {
    const dest = path.join(OUT, `${name}.webm`);
    fs.renameSync(path.join(OUT, newest), dest);
    console.log(`WROTE ${dest} ${fs.statSync(dest).size}B`);
  }
}

// Reel 3: 3-way terminal style switcher + theme + accent
async function reelStyle(page) {
  await page.goto('http://localhost:5180/?preview=terminal', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1200);
  await tap(page, 'Native pane', 1100);
  await tap(page, 'Floating glass', 1200);
  await tap(page, 'Full-bleed', 1200);
  await tap(page, 'Native pane', 900);
  // theme toggle (dark <-> light)
  await tap(page, 'dark', 1000);
  await tap(page, 'light', 900).catch(() => {});
  // accents
  for (const a of ['cyan', 'amber', 'magenta', 'green']) await tap(page, a, 650);
  await page.waitForTimeout(700);
}

// Reel 4: in-page annotator — draw an arrow + a note (do NOT send)
async function reelAnnotate(page) {
  await page.goto('http://localhost:5180/?preview=terminal', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1400);
  // open annotator
  await page.locator('button:has-text("✎")').first().click().catch(() => {});
  await page.waitForTimeout(1200);
  // draw an arrow across the terminal area
  const v = page.viewportSize();
  await page.mouse.move(v.width * 0.28, v.height * 0.30);
  await page.waitForTimeout(300);
  await page.mouse.down();
  for (let i = 0; i <= 20; i++) {
    await page.mouse.move(v.width * (0.28 + 0.40 * i / 20), v.height * (0.30 + 0.28 * i / 20));
    await page.waitForTimeout(20);
  }
  await page.mouse.up();
  await page.waitForTimeout(1100);
  // draw a second stroke (a box-ish underline) lower
  await page.mouse.move(v.width * 0.30, v.height * 0.62);
  await page.mouse.down();
  for (let i = 0; i <= 16; i++) { await page.mouse.move(v.width * (0.30 + 0.34 * i / 16), v.height * 0.62); await page.waitForTimeout(20); }
  await page.mouse.up();
  await page.waitForTimeout(1400);
}

// Reel 5: mobile web-shell with the accessory key bar (390x800)
async function reelMobile(page) {
  await page.goto('http://localhost:5180/?preview=webterm', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1500);
  const term = page.locator('.terminal, .xterm').first();
  await term.click().catch(() => {});
  await page.waitForTimeout(500);
  // type a command, then exercise accessory keys
  await page.keyboard.type('ls -la', { delay: 110 });
  await page.waitForTimeout(700);
  await page.keyboard.press('Enter');
  await page.waitForTimeout(900);
  await page.keyboard.type('cd /var', { delay: 110 });
  await page.waitForTimeout(600);
  // accessory bar: Tab, arrows, pipe, then Esc, ctrl
  for (const k of ['Tab', '↑', '↓', '←', '→', '|', 'Esc']) await tap(page, k, 650);
  // sticky ctrl toggle + a "C"
  await tap(page, 'ctrl', 700);
  await page.keyboard.type('c', { delay: 120 });
  await page.waitForTimeout(1000);
}

(async () => {
  const which = process.argv[2] || 'all';
  if (which === 'style' || which === 'all') await record('reel3-styleswitch', { width: 1280, height: 800 }, reelStyle);
  if (which === 'annotate' || which === 'all') await record('reel4-annotate', { width: 1280, height: 800 }, reelAnnotate);
  if (which === 'mobile' || which === 'all') await record('reel5-mobilekeys', { width: 390, height: 800 }, reelMobile);
  console.log('DONE');
})().catch(e => { console.error(e); process.exit(1); });
