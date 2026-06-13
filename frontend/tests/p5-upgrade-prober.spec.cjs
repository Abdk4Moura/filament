// P5 — relay→direct auto-upgrade prober (frontend transport gate).
//
// Mirrors runner/sim/relay_upgrade_test.sh's assertion contract on the BROWSER
// surface: a link on relay periodically probes for a direct path, VERIFIES it
// holds before committing (no flap), and on commit flips route→direct (which
// auto-clears the amber RELAY UI) and releases the relay. Plus the two guards:
// the kill-switch and the shared-ICE-restart (stall) guard.
//
// Drives the REAL PeerLink in real Chromium (the P0/P1 harness pattern; the
// chrome-devtools MCP multi-tab path wedges headless, so we use the
// esbuild→http→Playwright harness instead). ALSO asserts useFilament.js +
// webrtc.js source contain the load-bearing P5 wiring, to catch source drift.
//
//   node frontend/tests/p5-upgrade-prober.spec.cjs

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PW = '/root/wt-transport/experiments/ux/node_modules/playwright';
const { chromium } = require(PW);

const ROOT = path.resolve(__dirname, '..', '..');
const FRONT = path.join(ROOT, 'frontend');
const HARNESS_PORT = 8247;

let server = null;
function fail(msg) { console.error('[p5] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[p5] OK:', msg); }
function cleanup() { try { server && server.close(); } catch (e) {} }

function buildHarness() {
  const out = path.join(__dirname, '.p5-upgrade-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'p5-upgrade-prober-harness.jsx'), '--bundle', '--format=iife',
      `--outfile=${out}`, '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild harness bundle failed: ' + (r.stderr || r.stdout));
  return out;
}

function startServer(bundlePath) {
  const bundle = fs.readFileSync(bundlePath);
  const html = '<!doctype html><html><head><meta charset=utf-8></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  return new Promise((resolve) => server.listen(HARNESS_PORT, '127.0.0.1', resolve));
}

// ---- source-level invariants (guard against harness/source drift) ----------
function assertSource() {
  const hook = fs.readFileSync(path.join(FRONT, 'src', 'lib', 'useFilament.js'), 'utf8');
  const rtc = fs.readFileSync(path.join(FRONT, 'src', 'lib', 'webrtc.js'), 'utf8');
  const checks = [
    ['rtc has _armUpgradeProber', /_armUpgradeProber\s*\(\)\s*\{/.test(rtc)],
    ['rtc has _disarmUpgradeProber', /_disarmUpgradeProber\s*\(\)\s*\{/.test(rtc)],
    ['rtc has _upgradeProbe', /async\s+_upgradeProbe\s*\(\)/.test(rtc)],
    ['rtc has _beginUpgradeVerify (verify-before-commit)', /_beginUpgradeVerify\s*\(/.test(rtc)],
    ['rtc has _commitUpgrade with value-prop line', /_commitUpgrade\s*\(/.test(rtc) && /upgraded to direct — relay released/.test(rtc)],
    ['rtc arms on relayed / disarms on direct in _detectRoute',
      /route\s*===\s*'relayed'\)\s*this\._armUpgradeProber\(\)/.test(rtc) && /this\._disarmUpgradeProber\(\)/.test(rtc)],
    ['rtc kill-switch reads filamentUpgradeProbe', /localStorage\.getItem\('filamentUpgradeProbe'\)\s*===\s*'0'/.test(rtc)],
    ['rtc shared-ICE-restart guard (stallEpisode || !connected)',
      /connectionState\s*!==\s*'connected'\s*\|\|\s*this\._stallEpisode/.test(rtc)],
    ['rtc only impolite drives restartIce in probe', /if\s*\(!this\.polite\)\s*\{[\s\S]*?restartIce/.test(rtc)],
    ['rtc backoff first→steady (UPGRADE_FIRST_MS / UPGRADE_STEADY_MS)',
      /UPGRADE_FIRST_MS/.test(rtc) && /UPGRADE_STEADY_MS/.test(rtc) && /UPGRADE_VERIFY_MS/.test(rtc)],
    ['rtc exposes probeUpgradeNow', /probeUpgradeNow\s*\(\)\s*\{/.test(rtc)],
    ['rtc disarms prober in close() and _failActive()',
      (rtc.match(/_disarmUpgradeProber\(\)/g) || []).length >= 3],
    ['rtc persistent-freeze test seam (freezepersist + heal)',
      /freezePersist/.test(rtc) && /HEAL_AFTER_MS/.test(rtc)],
    ['hook nudges relayed links on network change (probeUpgradeNow)',
      /probeUpgradeNow\?\.\(\)/.test(hook)],
    ['hook listens for online + connection change', /addEventListener\('online'/.test(hook) && /navigator\.connection/.test(hook)],
  ];
  let allgood = true;
  for (const [name, pass] of checks) {
    if (pass) ok('source: ' + name);
    else { console.error('[p5] FAIL: source missing — ' + name); allgood = false; }
  }
  if (!allgood) fail('source-level invariants failed (P5 wiring may have drifted)');
}

(async () => {
  assertSource();
  const bundle = buildHarness();
  await startServer(bundle);
  ok('harness bundled + served');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 400)));
  page.on('console', (m) => { if (m.type() === 'error') console.log('[console-error]', m.text().slice(0, 300)); });
  // Tight prober timings via the URL knobs webrtc.js reads at module load: a 600ms
  // verify window keeps probe(1200ms settle)+verify well under the test budget.
  const q = 'upgradefirstms=80&upgradesteadyms=400&upgradeverifyms=600';
  await page.goto(`http://127.0.0.1:${HARNESS_PORT}/?${q}`, { waitUntil: 'load' });

  await page.waitForFunction(() => !!window.__P5, null, { timeout: 30000 });
  const out = await page.evaluate(() => window.__P5);

  if (out.error) fail('harness threw: ' + out.error);
  for (const r of out.results) {
    if (r.pass) ok(r.name + (r.detail ? ` (${r.detail})` : ''));
    else console.error('[p5] FAIL:', r.name, '—', r.detail);
  }
  await browser.close();
  cleanup();

  if (!out.passed) { console.error(`\n[p5] ${out.results.filter((r) => !r.pass).length}/${out.total} harness checks FAILED`); process.exit(1); }
  console.log(`\n[p5] ALL CHECKS PASSED (${out.total} harness + source invariants)`);
  process.exit(0);
})().catch((e) => { console.error('[p5] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
