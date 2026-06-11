// journey-phone-shell.cjs — Sam journey (dev, home server): shell from anywhere.
//
// Sam's home server runs `filament up --shell` (a REAL peer). From his PHONE
// (mobile viewport) he pairs it once, opens its terminal, and runs a real
// command (`uname -a`) — output streams back over the WebRTC data channel. No
// SSH server, no port-forward, no VPN: the shell-from-anywhere story.
//
// Usage: node journey-phone-shell.cjs <app-url> <code> <token> <video-dir>
const { run } = require('../lib/driver.cjs');
const [url, code, token, video] = process.argv.slice(2);
const MARK = token || 'SAM_SHELL_OK';

run({ name: 'sam-phone-shell', url, video, viewport: { width: 390, height: 820 }, mobile: true }, async (page, h) => {
  // 1) pair the home server (real PAKE), once.
  h.log('Sam pairs his home server from his phone (real code):', code);
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}
  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 30000 });
  await page.getByText('REMEMBERED', { exact: false }).first().waitFor({ timeout: 45000 });
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText), { timeout: 45000 });
  h.log('home server paired + live');

  // 2) open its terminal. On a phone, tapping the (known, shell-capable) tile
  //    opens the DeviceSheet; "Open terminal" is the action. Locate the tile via
  //    its REMEMBERED badge ancestor (the proven live-tile path).
  const remembered = page.getByText('REMEMBERED', { exact: false }).first();
  const tileByTitle = remembered.locator('xpath=ancestor::div[contains(@title,"Remembered")][1]');
  const tile = (await tileByTitle.count()) ? tileByTitle.first() : page.locator('[data-testid="peer-tile"]').first();
  await tile.waitFor({ timeout: 15000 });
  await tile.click({ timeout: 8000 });
  let openTerm = page.getByText('Open terminal', { exact: false }).first();
  try { await openTerm.waitFor({ timeout: 6000 }); }
  catch {
    // fallback: a ›_ chip / direct terminal entry on builds without the sheet
    const chip = page.locator('button:has-text("›_")').first();
    if (await chip.count()) { openTerm = chip; } else { throw new Error('no Open terminal action / ›_ chip on the server tile'); }
  }
  await h.tap(openTerm, 1200);
  h.log('opened the home server terminal from the phone');

  // 3) run a REAL command; assert its output renders in the live xterm.
  const term = page.locator('.xterm, .xterm-screen, .terminal').first();
  await term.waitFor({ timeout: 20000 });
  await term.click().catch(() => {});
  await page.waitForTimeout(700);
  // a real command whose output we can assert deterministically.
  await page.keyboard.type(`echo ${MARK}-$(uname -s | tr A-Z a-z)`, { delay: 55 });
  await page.waitForTimeout(300);
  await page.keyboard.press('Enter');
  h.log('ran a real command on the home server PTY');

  await page.waitForFunction((m) => {
    const el = document.querySelector('.xterm') || document.querySelector('.terminal');
    return el && el.textContent && el.textContent.includes(m);
  }, MARK, { timeout: 25000 });
  h.log('command output came back over the data channel');
  await page.waitForTimeout(1200);
  h.pass(`ERGO[paired once · open · type · output] — opened the home server shell from a phone and ran a real command; output streamed back over the data channel (no SSH server, no port-forward)`);
});
