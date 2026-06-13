// P1 — relay-preferred rebuild on persistent stall (frontend transport gate).
//
// Drives the REAL PeerLink in a real browser (Chromium via Playwright):
//   - the threaded relayOnly flag -> a live RTCPeerConnection with
//     iceTransportPolicy:'relay' (and a plain link stays default);
//   - the REAL P0 _correctStall ladder climbs a->b->c and fires
//     onStall({reason:'persistent'}) (the P0->P1 handoff);
//   - the hook's onStall decision: rebuild relay-preferred ONCE, no re-escalate
//     on an already-relay link, no escalate on a non-persistent reason, bounded
//     at-most-once (no rebuild loop), partials/outgoing preserved (resume).
//
// To defend against the harness's faithful-copy of the hook handler drifting
// from source, this spec ALSO asserts useFilament.js itself contains the
// load-bearing onStall wiring (relayOnly guard, relayedRef at-most-once,
// makeLinkRef({relayOnly:true})) and that webrtc.js threads iceTransportPolicy.
//
//   node frontend/tests/p1-relay-rebuild.spec.cjs

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PW = '/root/wt-transport/experiments/ux/node_modules/playwright';
const { chromium } = require(PW);

const ROOT = path.resolve(__dirname, '..', '..');
const FRONT = path.join(ROOT, 'frontend');
const HARNESS_PORT = 8243;

let server = null;
function fail(msg) { console.error('[p1] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[p1] OK:', msg); }
function cleanup() { try { server && server.close(); } catch (e) {} }

function buildHarness() {
  const out = path.join(__dirname, '.p1-relay-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'p1-relay-rebuild-harness.jsx'), '--bundle', '--format=iife',
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
    ['hook declares relayedRef', /relayedRef\s*=\s*useRef\(new Map\(\)\)/.test(hook)],
    ['hook makeLink accepts relayOnly', /\(\{\s*id,\s*name,\s*uid,\s*relayOnly\s*\}\)/.test(hook)],
    ['hook threads relayOnly into PeerLink', /relayOnly:\s*!!relayOnly/.test(hook)],
    ['hook wires onStall handler', /onStall:\s*\(\{\s*reason\s*\}\)\s*=>/.test(hook)],
    ['onStall guards non-persistent', /if\s*\(reason\s*!==\s*'persistent'\)\s*return/.test(hook)],
    ['onStall guards already-relay (no re-escalate)', /if\s*\(relayOnly\)/.test(hook)],
    ['onStall bounds at-most-once via relayedRef', /relayedRef\.current\.get\(id\)/.test(hook) && /relayedRef\.current\.set\(id,\s*r\s*\+\s*1\)/.test(hook)],
    ['onStall rebuilds with relayOnly:true', /makeLinkRef\.current\?\.\(\{\s*id,\s*name,\s*uid,\s*relayOnly:\s*true\s*\}\)/.test(hook)],
    ['webrtc PeerLink ctor accepts relayOnly', /constructor\(\{[^}]*\brelayOnly\b/.test(rtc)],
    ['webrtc threads iceTransportPolicy:relay', /iceTransportPolicy:\s*'relay'/.test(rtc)],
  ];
  let allgood = true;
  for (const [name, pass] of checks) {
    if (pass) ok('source: ' + name);
    else { console.error('[p1] FAIL: source missing — ' + name); allgood = false; }
  }
  if (!allgood) fail('source-level invariants failed (handler may have drifted)');
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
  await page.goto(`http://127.0.0.1:${HARNESS_PORT}/`, { waitUntil: 'load' });

  // Wait for the harness to publish its results.
  await page.waitForFunction(() => !!window.__P1, null, { timeout: 15000 });
  const out = await page.evaluate(() => window.__P1);

  if (out.error) fail('harness threw: ' + out.error);
  for (const r of out.results) {
    if (r.pass) ok(r.name + (r.detail ? ` (${r.detail})` : ''));
    else console.error('[p1] FAIL:', r.name, '—', r.detail);
  }
  await browser.close();
  cleanup();

  if (!out.passed) { console.error(`\n[p1] ${out.results.filter((r) => !r.pass).length}/${out.total} harness checks FAILED`); process.exit(1); }
  console.log(`\n[p1] ALL CHECKS PASSED (${out.total} harness + source invariants)`);
  process.exit(0);
})().catch((e) => { console.error('[p1] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
