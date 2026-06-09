// PAKE-UX gate (webui-pake-ux). Drives the REAL built UI through the two
// changed flows and FAILS on the prior regression:
//   Change 1 — cursor-safe auto-dash code entry (the regression: a naive
//              every-keystroke reformat jumps the caret to the end, so a
//              mid-string edit corrupts the value).
//   Change 2 — the v2 remember-consent PakeKeepBanner.
//
// Run (playwright + chromium come from cli/tests/node_modules):
//   node frontend/tests/pake-ux.spec.cjs        (from the repo root)
// The script self-adds cli/tests/node_modules to the resolution path, so no
// NODE_PATH or cwd juggling is needed.
//
// It starts a LOCAL backend serving frontend/dist SAME-ORIGIN (a prod-pointing
// dist makes every Playwright nav time out — see cli/tests/gates.sh), loads
// /rooms/<room> (link scope renders the "pair with code" affordance), and:
//   1. opens the code entry, types "grand hawk ruby 8045" CHAR-BY-CHAR ->
//      asserts value === "GRAND-HAWK-RUBY-8045".
//   2. THE REGRESSION CHECK: moves the caret into the middle, types a
//      transform-triggering lowercase char then a chained second char, and
//      asserts the exact resulting string. A naive reformat (caret -> end)
//      produces a DIFFERENT string here and fails.
//   3. pastes "GRAND-HAWK-RUBY-8045" -> asserts value.
//   4. consent: serves a focused Filament render harness with an injected
//      pendingPakeKeep and asserts the PakeKeepBanner shows, the name is
//      editable, and remember/not-now fire with the edited name.

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const Module = require('module');

// playwright lives in cli/tests/node_modules (per the repo's browser gates).
// Add it to the resolution path so this test runs from anywhere with a plain
// `node frontend/tests/pake-ux.spec.cjs`.
const CLI_TESTS_NM = path.resolve(__dirname, '..', '..', 'cli', 'tests', 'node_modules');
if (fs.existsSync(CLI_TESTS_NM) && !Module.globalPaths.includes(CLI_TESTS_NM)) {
  Module.globalPaths.push(CLI_TESTS_NM);
  process.env.NODE_PATH = (process.env.NODE_PATH ? process.env.NODE_PATH + path.delimiter : '') + CLI_TESTS_NM;
  Module._initPaths();
}
const { chromium } = require(path.join(CLI_TESTS_NM, 'playwright'));

const ROOT = path.resolve(__dirname, '..', '..');           // repo root
const FRONT = path.join(ROOT, 'frontend');
const BACKEND = path.join(ROOT, 'backend');
const DIST = path.join(FRONT, 'dist');
const VENV_PY = process.env.FILAMENT_TEST_VENV
  || '/root/.claude/jobs/330c2366/tmp/venv/bin/python';
const BACK_PORT = 8231;
const HARNESS_PORT = 8232;
const BACK_URL = `http://127.0.0.1:${BACK_PORT}`;

let backendProc = null;
let harnessServer = null;

function fail(msg) { console.error('[pake-ux] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[pake-ux] OK:', msg); }
function cleanup() {
  try { backendProc && backendProc.kill('SIGKILL'); } catch (e) {}
  try { harnessServer && harnessServer.close(); } catch (e) {}
}

async function waitHealth(timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const up = await new Promise((res) => {
      const req = http.get(`${BACK_URL}/api/health`, (r) => { r.resume(); res(r.statusCode === 200); });
      req.on('error', () => res(false));
      req.setTimeout(1000, () => { req.destroy(); res(false); });
    });
    if (up) return true;
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

function startBackend() {
  // Mirror gates.sh: eventlet, self monkeypatch, claim limit sky-high (we make
  // no claims here but keep it hermetic), serves frontend/dist at its origin.
  backendProc = spawn(VENV_PY, ['app.py'], {
    cwd: BACKEND,
    env: { ...process.env, PORT: String(BACK_PORT), FIL_ASYNC_MODE: 'eventlet',
      FIL_SELF_MONKEYPATCH: '1', FIL_CLAIM_LIMIT: '1000000',
      FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  backendProc.stdout.on('data', () => {});
  backendProc.stderr.on('data', () => {});
}

// Bundle the focused consent harness with the project's esbuild and serve it +
// a tiny index.html on HARNESS_PORT. Pure render — no backend needed.
function buildHarness() {
  const out = path.join(__dirname, '.pakekeep-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'pakekeep-harness.jsx'), '--bundle', '--format=iife',
      `--outfile=${out}`, '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild harness bundle failed: ' + (r.stderr || r.stdout));
  return out;
}

function startHarnessServer(bundlePath) {
  const bundle = fs.readFileSync(bundlePath);
  const html = '<!doctype html><html><head><meta charset=utf-8></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  harnessServer = http.createServer((req, res) => {
    if (req.url === '/bundle.js') { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  return new Promise((resolve) => harnessServer.listen(HARNESS_PORT, '127.0.0.1', resolve));
}

(async () => {
  if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built — run `VITE_FILAMENT_API= npm run build` in frontend/');
  // Guard the documented red herring: a prod-pointing dist times out every nav.
  const bundleJs = fs.readdirSync(path.join(DIST, 'assets')).filter((f) => f.endsWith('.js'));
  for (const f of bundleJs) {
    if (fs.readFileSync(path.join(DIST, 'assets', f), 'utf8').includes('api.filament.autumated.com'))
      fail('dist is prod-pointing — rebuild SAME-ORIGIN: `VITE_FILAMENT_API= npm run build`');
  }
  ok('dist present and same-origin');

  startBackend();
  if (!await waitHealth(30000)) fail('backend did not come up at ' + BACK_URL);
  ok('backend up');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 300)));

  // ---- Change 1: cursor-safe auto-dash on the REAL UI -----------------------
  await page.goto(`${BACK_URL}/rooms/demo-${Date.now()}`, { waitUntil: 'networkidle' });
  ok('page loaded (link scope)');

  // Open the code entry.
  const pairBtn = page.getByText('pair with code', { exact: true }).first();
  await pairBtn.waitFor({ timeout: 30000 });
  await pairBtn.click();
  const input = page.getByPlaceholder('ENTER CODE');
  await input.waitFor({ timeout: 10000 });
  await input.click();
  ok('code entry open');

  // 1) Type a multi-word code CHAR BY CHAR; spaces must auto-dash.
  for (const ch of 'grand hawk ruby 8045') await page.keyboard.press(ch === ' ' ? 'Space' : ch);
  let val = await input.inputValue();
  if (val !== 'GRAND-HAWK-RUBY-8045') fail(`char-by-char value was "${val}", expected "GRAND-HAWK-RUBY-8045"`);
  ok('char-by-char typed -> GRAND-HAWK-RUBY-8045');

  // 2) THE REGRESSION CHECK. Place the caret right after "GRAND" (offset 5),
  //    type a transform-triggering lowercase 'x' then a chained 'y'. A correct
  //    cursor-safe impl keeps the caret in place -> "GRANDXY-HAWK-RUBY-8045".
  //    The naive every-keystroke reformat resets the caret to the END after the
  //    first ('x' uppercases -> value changes -> React resets caret), so 'y'
  //    lands at the tail -> "GRANDX-HAWK-RUBY-8045Y". Distinct, asserted exactly.
  await input.evaluate((el) => el.setSelectionRange(5, 5));
  await page.keyboard.press('x');
  await page.keyboard.press('y');
  val = await input.inputValue();
  if (val !== 'GRANDXY-HAWK-RUBY-8045')
    fail(`mid-string edit corrupted (caret regression): got "${val}", expected "GRANDXY-HAWK-RUBY-8045"`);
  ok('mid-string edit caret-stable -> GRANDXY-HAWK-RUBY-8045');

  // 2b) Backspace at the caret removes the char BEFORE it (not at the tail).
  //     Caret is just after the 'y' (offset 7). Backspace -> drop 'Y'.
  await page.keyboard.press('Backspace');
  val = await input.inputValue();
  if (val !== 'GRANDX-HAWK-RUBY-8045')
    fail(`backspace at caret wrong: got "${val}", expected "GRANDX-HAWK-RUBY-8045"`);
  ok('backspace at caret correct -> GRANDX-HAWK-RUBY-8045');

  // 3) Paste of the dashed form yields the same value. React controls value, so
  //    clear via select-all + delete, then dispatch a native input event with
  //    the pasted string (the prototype setter bypasses React's value tracker).
  await page.keyboard.press('Control+A');
  await page.keyboard.press('Delete');
  await input.evaluate((el) => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(el, 'GRAND-HAWK-RUBY-8045');
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
  val = await input.inputValue();
  if (val !== 'GRAND-HAWK-RUBY-8045') fail(`paste value was "${val}", expected "GRAND-HAWK-RUBY-8045"`);
  ok('paste GRAND-HAWK-RUBY-8045 -> value correct');

  // ---- Change 2: consent banner (focused Filament render) -------------------
  const bundle = buildHarness();
  await startHarnessServer(bundle);
  const hpage = await browser.newPage();
  hpage.on('pageerror', (e) => console.log('[harness-page-error]', String(e).slice(0, 300)));
  await hpage.goto(`http://127.0.0.1:${HARNESS_PORT}/`, { waitUntil: 'networkidle' });

  // Banner present with the "remember"/"not now" affordances.
  await hpage.getByText('Remember', { exact: false }).first().waitFor({ timeout: 10000 });
  const rememberBtn = hpage.getByRole('button', { name: 'remember' });
  const notNowBtn = hpage.getByRole('button', { name: 'not now' });
  if (!(await rememberBtn.count())) fail('consent: "remember" button missing');
  if (!(await notNowBtn.count())) fail('consent: "not now" button missing');
  ok('PakeKeepBanner shows with remember/not-now');

  // Editable name: default = peer display name, editable, accept fires with it.
  const nameField = hpage.locator('input[placeholder="device"]');
  await nameField.waitFor({ timeout: 5000 });
  if ((await nameField.inputValue()) !== 'pixel') fail('consent: name field default should be peer name "pixel"');
  await nameField.click();
  await nameField.fill('my-laptop');
  await rememberBtn.click();
  const accepted = await hpage.evaluate(() => window.__pakeAccept);
  if (!accepted || accepted.peerId !== 'peer-abc123' || accepted.name !== 'my-laptop')
    fail('consent: accept did not fire with edited name; got ' + JSON.stringify(accepted));
  ok('editable name + remember fires acceptPakeKeep("peer-abc123","my-laptop")');

  await browser.close();
  cleanup();
  console.log('\n[pake-ux] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => { console.error('[pake-ux] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
