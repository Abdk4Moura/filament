// Relay-honesty UX gate (transport-resilience P1, frontend half).
// Relay (TURN) is still E2E-encrypted but is NOT a direct link, so it must be
// LOUD and HONEST. This drives the REAL Filament component (focused render
// harness, mirroring pakekeep-harness) with an injected roster of two relayed
// peers + one direct peer, and asserts:
//   1. a relayed peer's tile shows the amber ⚠ "RELAY" chip + "· via relay";
//   2. the device sheet's Info section spells out the honest explainer;
//   3. the global "N on relay" top-bar indicator appears and COUNTS relayed
//      peers (2 here);
//   4. the direct peer carries NO relay warning;
//   5. with an all-direct roster the global indicator is HIDDEN.
// Screenshots are written for BOTH themes. No backend needed (pure render).
//
//   node frontend/tests/relay-honesty.spec.cjs

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

// Playwright + cached chromium come from the ux experiment (per the task).
const PW = '/root/wt-transport/experiments/ux/node_modules/playwright';
const { chromium } = require(PW);

const ROOT = path.resolve(__dirname, '..', '..');
const FRONT = path.join(ROOT, 'frontend');
const HARNESS_PORT = 8242;
const SHOT_DIR = path.join(__dirname, '.relay-shots');

let harnessServer = null;
function fail(msg) { console.error('[relay-honesty] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[relay-honesty] OK:', msg); }
function cleanup() { try { harnessServer && harnessServer.close(); } catch (e) {} }

function buildHarness() {
  const out = path.join(__dirname, '.relay-honesty-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'relay-honesty-harness.jsx'), '--bundle', '--format=iife',
      `--outfile=${out}`, '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild harness bundle failed: ' + (r.stderr || r.stdout));
  return out;
}

function startHarnessServer(bundlePath) {
  const bundle = fs.readFileSync(bundlePath);
  const html = '<!doctype html><html><head><meta charset=utf-8></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  harnessServer = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  return new Promise((resolve) => harnessServer.listen(HARNESS_PORT, '127.0.0.1', resolve));
}

(async () => {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  const bundle = buildHarness();
  await startHarnessServer(bundle);
  ok('harness bundled + served');

  const browser = await chromium.launch({ headless: true });

  for (const theme of ['dark', 'light']) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 300)));
    await page.goto(`http://127.0.0.1:${HARNESS_PORT}/?theme=${theme}`, { waitUntil: 'networkidle' });

    // ---- 1. relayed tile shows the amber ⚠ chip -----------------------------
    const relayChips = page.locator('[data-testid="route-relay"]');
    const chipCount = await relayChips.count();
    if (chipCount !== 2) fail(`[${theme}] expected 2 relay route chips, got ${chipCount}`);
    const chipText = (await relayChips.first().innerText()).replace(/\s+/g, ' ').trim();
    if (!chipText.includes('⚠') || !/RELAY/i.test(chipText))
      fail(`[${theme}] relay chip text was "${chipText}", expected ⚠ + RELAY`);
    // Amber, not the calm accent: the chip's color must be the warn token.
    const chipColor = await relayChips.first().evaluate((el) => getComputedStyle(el).color);
    const warnRGB = theme === 'dark' ? 'rgb(255, 200, 87)' : 'rgb(154, 107, 0)';
    if (chipColor !== warnRGB) fail(`[${theme}] relay chip color ${chipColor}, expected amber ${warnRGB}`);
    ok(`[${theme}] 2 relayed tiles show amber ⚠ RELAY chip`);

    // tooltip / explainer carried on the chip (honest wording).
    const chipTitle = await relayChips.first().getAttribute('title');
    if (!chipTitle || !/not a direct link/i.test(chipTitle) || !/end-to-end encrypted/i.test(chipTitle))
      fail(`[${theme}] relay chip title missing honest explainer: "${chipTitle}"`);
    ok(`[${theme}] relay chip carries honest explainer tooltip`);

    // status line says "· via relay" (survives a scrolled-off chip).
    if (!(await page.getByText('· via relay').first().count()))
      fail(`[${theme}] tile status line missing "· via relay"`);
    ok(`[${theme}] tile status line says "· via relay"`);

    // ---- 2. direct peer has NO relay warning --------------------------------
    // The direct tile ("my-laptop") must not contain a relay chip nor "via relay".
    const directTile = page.locator('[data-testid="peer-tile"][data-route="direct"]').first();
    if (!(await directTile.count())) fail(`[${theme}] direct peer tile not found`);
    if (await directTile.locator('[data-testid="route-relay"]').count())
      fail(`[${theme}] direct peer tile has a relay chip (expected none)`);
    if ((await directTile.innerText()).includes('via relay'))
      fail(`[${theme}] direct peer tile says "via relay" (expected none)`);
    // And the relayed tiles must NOT bleed their warning into the direct one:
    // sanity that the relay chips live only under relayed tiles.
    const chipsUnderDirect = await page.locator('[data-testid="peer-tile"][data-route="direct"] [data-testid="route-relay"]').count();
    if (chipsUnderDirect !== 0) fail(`[${theme}] relay chip leaked into direct tile`);
    ok(`[${theme}] direct peer tile carries NO relay warning`);

    // ---- 3. global indicator appears + counts relayed peers -----------------
    const banner = page.locator('[data-testid="relay-banner"]').first();
    if (!(await banner.count())) fail(`[${theme}] global relay banner missing`);
    const bannerText = (await banner.innerText()).replace(/\s+/g, ' ').trim();
    if (!/2 on relay/.test(bannerText)) fail(`[${theme}] global banner "${bannerText}" should read "2 on relay"`);
    const bannerTitle = await banner.getAttribute('title');
    if (!bannerTitle || !/not a direct link/i.test(bannerTitle))
      fail(`[${theme}] global banner title missing explainer: "${bannerTitle}"`);
    ok(`[${theme}] global indicator shows "⚠ 2 on relay" with explainer`);

    // ---- 4. device sheet explainer (open the relayed remembered tile) -------
    // Right-click the pixel-7 tile to open the DeviceSheet (desktop path).
    const pixelName = page.getByText('pixel-7', { exact: true }).first();
    await pixelName.click({ button: 'right' });
    const sheetExplainer = page.locator('[data-testid="sheet-relay-explainer"]').first();
    await sheetExplainer.waitFor({ timeout: 5000 });
    const sheetText = (await sheetExplainer.innerText()).replace(/\s+/g, ' ').trim();
    if (!/not a direct link/i.test(sheetText) || !/end-to-end encrypted/i.test(sheetText))
      fail(`[${theme}] sheet relay explainer wrong: "${sheetText}"`);
    ok(`[${theme}] device sheet Info shows the honest relay explainer`);
    await page.keyboard.press('Escape');

    await page.screenshot({ path: path.join(SHOT_DIR, `relay-${theme}.png`), fullPage: false });
    ok(`[${theme}] screenshot -> ${path.join(SHOT_DIR, `relay-${theme}.png`)}`);
    await page.close();
  }

  // ---- 5. all-direct roster: global indicator HIDDEN, no relay anywhere -----
  const dpage = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  dpage.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 300)));
  await dpage.goto(`http://127.0.0.1:${HARNESS_PORT}/?theme=dark&allDirect=1`, { waitUntil: 'networkidle' });
  const directOnly = await dpage.evaluate(() => ({
    banners: document.querySelectorAll('[data-testid="relay-banner"]').length,
    chips: document.querySelectorAll('[data-testid="route-relay"]').length,
    viaRelay: /via relay/.test(document.body.textContent || ''),
  }));
  if (directOnly.banners !== 0) fail(`all-direct: global banner should be HIDDEN, found ${directOnly.banners}`);
  if (directOnly.chips !== 0) fail(`all-direct: found ${directOnly.chips} relay chips, expected 0`);
  if (directOnly.viaRelay) fail('all-direct: "via relay" text present, expected none');
  ok('all-direct roster: global indicator HIDDEN, zero relay warnings');
  await dpage.close();

  await browser.close();
  cleanup();
  console.log('\n[relay-honesty] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => { console.error('[relay-honesty] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
