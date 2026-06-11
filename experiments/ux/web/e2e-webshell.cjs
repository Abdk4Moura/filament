// e2e-webshell.cjs — REAL web-shell: a paired `up --shell` peer advertises a
// terminal; the human opens it (›_ chip), types a real command, and we ASSERT
// the command's output renders in the live xterm (PTY over the data channel).
//
// The caller has ALREADY paired the browser with the shell peer (CLI minted a
// code; this same browser context is reused / or the store is pre-seeded via the
// real pair flow in the same run). We accept the code on argv and pair first so
// this driver is self-contained.
//
// Usage: node e2e-webshell.cjs <app-url> <4-segment-code> <token> <video-dir>
const { run } = require('../lib/driver.cjs');
const [url, code, token, video] = process.argv.slice(2);
const MARK = token || 'FILA_SHELL_OK';

run({ name: 'web-shell', url, video, viewport: { width: 1100, height: 720 } }, async (page, h) => {
  // 1) real pairing with the shell peer (human types the minted code)
  h.log('pairing with the up --shell peer, code:', code);
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}
  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 30000 });
  h.log('paired — device remembered');

  // 2) wait for the device to reach a live 'ready' link (real WebRTC data
  //    channel up + the CLI's `caps` message marking peer.shell), then HOVER the
  //    remembered tile — the ›_ open-terminal chip lives in the hover action bar.
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText),
    { timeout: 40000 });
  h.log('device link is ready');
  const tile = page.locator('div', { hasText: 'REMEMBERED' }).last();
  let chip = page.locator('button:has-text("›_")').first();
  for (let i = 0; i < 20 && !(await chip.count()); i++) {
    await tile.hover({ timeout: 4000 }).catch(() => {});
    await page.waitForTimeout(700);
    chip = page.locator('button:has-text("›_")').first();
  }
  await chip.waitFor({ timeout: 8000 });
  h.log('shell chip (›_) revealed on hover — device advertised a terminal');
  await h.tap(chip, 1500);

  // 3) the WebTerminal mounts + opens a PTY over the data channel. Type a real
  //    command and assert its output lands in xterm scrollback.
  const term = page.locator('.xterm, .xterm-screen, .terminal').first();
  await term.waitFor({ timeout: 20000 });
  await term.click().catch(() => {});
  await page.waitForTimeout(800);
  await page.keyboard.type(`echo ${MARK}`, { delay: 70 });
  await page.waitForTimeout(400);
  await page.keyboard.press('Enter');
  h.log('typed real command into the live PTY');

  // ASSERT: the marker appears in the rendered terminal (output came back)
  await page.waitForFunction((m) => {
    const el = document.querySelector('.xterm') || document.querySelector('.terminal');
    return el && el.textContent && el.textContent.includes(m);
  }, MARK, { timeout: 25000 });
  h.log('command output rendered in xterm — PTY round-trip OK');
  await page.waitForTimeout(1200);
  h.pass('paired up --shell peer; opened a real terminal; typed a command; saw its output over the data channel');
});
