// Gate 16: known-device rendezvous — the browser half of C12/C20/C27.
//
// Phase 1: a real Chromium tab claims a `--word --remember` sender's code.
// C27: remembering needs HUMAN consent — the banner appears, we click
// "remember", and only then must the secret be in localStorage.
//
// Phase 2: a brand-new CLI session runs `send --to <name> --room <isolated>` —
// NO shared room, NO code. The only way it can find this tab is the
// secret-derived presence channel. The offer appearing here proves the whole
// chain: consent -> store -> subscribe -> known-peer -> link -> proof.
//
// Phase 3 (decline): a third sender offers to be remembered and we click
// "not now" — the pair-keep-ack{ok:false} must make THAT sender discard its
// half (gates.sh asserts its log and the device store).
//
// Usage: node known-device.js <app-url> <word-code> <decline-word-code>
const { chromium } = require('playwright');

(async () => {
  const url = process.argv[2] || 'http://127.0.0.1:8077/';
  const code = process.argv[3];
  const declineCode = process.argv[4];
  const browser = await chromium.launch({ headless: true });
  const page = await (await browser.newContext()).newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));

  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[pw] app loaded');

  // ---- phase 1: claim, consent to remember, accept, complete --------------
  await page.getByText('pair with code', { exact: true }).first().click();
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.getByText('pair', { exact: true }).first().click();
  console.log('[pw] code submitted');

  // C27 consent banner — the secret must NOT be stored before this click
  const remember = page.getByText('remember', { exact: true }).first();
  await remember.waitFor({ timeout: 60000 });
  const before = await page.evaluate(() => localStorage.getItem('filament-known-devices') || '[]');
  if (JSON.parse(before).length > 0) throw new Error('secret stored BEFORE consent');
  await remember.click();
  console.log('[pw] consent given');

  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 15000 });
  console.log('[pw] SECRET STORED');

  const accept1 = page.getByText('accept', { exact: true }).first();
  await accept1.waitFor({ timeout: 60000 });
  await accept1.click();
  await page.getByText('save', { exact: true }).first().waitFor({ timeout: 60000 });
  console.log('[pw] PHASE1 COMPLETE');

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

  // ---- phase 3: decline a remember offer; the sender must discard ---------
  if (declineCode) {
    await new Promise((r) => setTimeout(r, 6000)) // let gates.sh start the sender
    // phase 1's claim left us in the 'Paired privately' bar, which hides the
    // code buttons — return to the auto room first.
    await page.getByText('← back to nearby', { exact: true }).first().click();
    await page.getByText('pair with code', { exact: true }).first().click();
    await page.getByPlaceholder('ENTER CODE').fill(declineCode);
    await page.getByText('pair', { exact: true }).first().click();
    const notNow = page.getByText('not now', { exact: true }).first();
    await notNow.waitFor({ timeout: 60000 });
    await notNow.click();
    await new Promise((r) => setTimeout(r, 2500)) // let the ack reach the sender
    console.log('[pw] PHASE3 DECLINED');
  }

  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 300));
  process.exit(1);
});
