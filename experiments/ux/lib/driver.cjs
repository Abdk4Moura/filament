// driver.cjs — shared Playwright harness for the REAL-app e2e drivers.
//
// Every driver below opens the REAL built filament app (served same-origin by
// our local backend), drives it with human-like gestures, ASSERTS real DOM /
// localStorage state, and records the tab to a VP8/webm. No ?preview= mock seam
// is used for these e2e flows (preview stays only for the pure-visual reels).
//
// Usage in a driver:
//   const { run } = require('./driver.cjs');
//   run({ name, url, viewport, video }, async (page, h) => { ... h.pass()/h.fail() });
const { chromium } = require('playwright');

// chromium masks loopback host ICE behind mDNS .local names the CLI can't
// resolve; disabling it makes single-host CLI<->browser ICE complete. (Prod is
// cross-host with real IPs, so this is purely a single-host test accommodation.)
const ARGS = ['--no-sandbox', '--disable-dev-shm-usage',
  '--disable-features=WebRtcHideLocalIpsWithMdns',
  '--force-fieldtrials=WebRTC-Mdns/Disabled/'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// gentle human click on a text/locator
async function tap(page, sel, hold = 500) {
  const loc = typeof sel === 'string' ? page.locator(sel).first() : sel;
  await loc.hover({ timeout: 3000 }).catch(() => {});
  await sleep(180);
  await loc.click({ timeout: 4000 });
  await sleep(hold);
}

async function run(opts, fn) {
  const { name, url, viewport = { width: 1000, height: 700 }, video, record = true, mobile = false } = opts;
  const browser = await chromium.launch({ headless: true, args: ARGS });
  const ctxOpts = { viewport, deviceScaleFactor: 1 };
  if (record && video) ctxOpts.recordVideo = { dir: video, size: viewport };
  if (mobile) { ctxOpts.hasTouch = true; ctxOpts.isMobile = true; }
  const ctx = await browser.newContext(ctxOpts);
  const page = await ctx.newPage();
  page.setDefaultTimeout(8000);
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));

  let verdict = 'FAIL', detail = `${name}: did not complete`;
  const h = {
    sleep, tap: (s, hold) => tap(page, s, hold),
    pass: (d) => { verdict = 'PASS'; detail = d || detail; },
    fail: (d) => { verdict = 'FAIL'; detail = d || detail; },
    log: (...a) => console.log('[web]', ...a),
  };
  try {
    await page.goto(url, { waitUntil: 'networkidle' });
    await fn(page, h);
  } catch (e) {
    detail = `${name}: ${String(e.message || e).slice(0, 220)}`;
    verdict = 'FAIL';
  } finally {
    await page.waitForTimeout(400);
    await page.close().catch(() => {});
    await ctx.close().catch(() => {});   // flush video
    await browser.close().catch(() => {});
  }
  // machine-readable line the shell case reads:
  console.log(`PIPE_RESULT ${verdict} ${detail}`);
  process.exit(verdict === 'PASS' ? 0 : 1);
}

module.exports = { run, tap, sleep, ARGS };
