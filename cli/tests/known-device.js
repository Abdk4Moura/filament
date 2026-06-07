// Gate 16: known-device rendezvous — the browser half of C12/C20.
//
// Phase 1: a real Chromium tab claims a `--word --remember` sender's code,
// accepts the transfer, and must end up having STORED the pair secret the
// sender handed over via pair-keep (mutual acknowledgement, not one-sided).
//
// Phase 2: a brand-new CLI session runs `send --to <name> --room <isolated>` —
// NO shared room, NO code. The only way it can find this tab is the
// secret-derived presence channel. The offer appearing here proves the whole
// chain: store -> subscribe -> known-peer -> link -> proof -> transfer.
//
// Usage: node known-device.js <app-url> <word-code>
const { chromium } = require('playwright');

(async () => {
  const url = process.argv[2] || 'http://127.0.0.1:8077/';
  const code = process.argv[3];
  const browser = await chromium.launch({ headless: true });
  const page = await (await browser.newContext()).newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));

  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[pw] app loaded');

  // ---- phase 1: claim the code, accept, complete --------------------------
  await page.getByText('pair with code', { exact: true }).first().click();
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.getByText('pair', { exact: true }).first().click();
  console.log('[pw] code submitted');

  const accept1 = page.getByText('accept', { exact: true }).first();
  await accept1.waitFor({ timeout: 60000 });
  await accept1.click();
  await page.getByText('save', { exact: true }).first().waitFor({ timeout: 60000 });
  console.log('[pw] PHASE1 COMPLETE');

  // pair-keep must have landed in localStorage (and re-raised the channel)
  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 15000 });
  console.log('[pw] SECRET STORED');

  // ---- phase 2: a fresh CLI session must find us with no room, no code ----
  const accept2 = page.getByText('accept', { exact: true }).first();
  await accept2.waitFor({ timeout: 90000 });
  await accept2.click();
  // a SECOND completed transfer = a second 'save' affordance
  await page.waitForFunction(() => {
    const saves = [...document.querySelectorAll('*')]
      .filter((e) => e.childElementCount === 0 && e.textContent.trim() === 'save')
    return saves.length >= 2
  }, { timeout: 60000 });
  console.log('[pw] PHASE2 COMPLETE (channel rendezvous, no code)');

  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 300));
  process.exit(1);
});
