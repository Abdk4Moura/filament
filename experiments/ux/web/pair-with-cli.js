// Scenario 10 browser half: claim the CLI's PAKE pairing code via "pair with
// code", give the remember consent, and confirm the device is stored in
// localStorage. Records a webm of the tab.
// Usage:  node pair-with-cli.js <app-url> <4-segment-code> <video-dir>
const { chromium } = require('playwright');
const MDNS_OFF = ['--disable-features=WebRtcHideLocalIpsWithMdns',
                  '--force-fieldtrials=WebRTC-Mdns/Disabled/'];

(async () => {
  const [url, code, videoDir] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true,
    args: ['--no-sandbox','--disable-dev-shm-usage', ...MDNS_OFF] });
  const ctx = await browser.newContext({
    recordVideo: { dir: videoDir, size: { width: 900, height: 620 } },
    viewport: { width: 900, height: 620 },
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));
  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[web] app loaded — pairing with the CLI code:', code);

  await page.getByText('pair with code', { exact: true }).first().click();
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(500);
  await page.getByText('pair', { exact: true }).first().click();
  console.log('[web] code submitted');

  // PAKE pairing completes; the device gets stored. Some builds gate the store
  // behind a 'remember' consent banner — click it if present, else the store
  // happens on pake-paired.
  try {
    const remember = page.getByText('remember', { exact: true }).first();
    await remember.waitFor({ timeout: 8000 });
    await remember.click();
    console.log('[web] remember consent given');
  } catch { /* no banner — store is automatic on pair */ }

  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 30000 });
  console.log('[web] SECRET STORED (device remembered in the browser)');
  await page.waitForTimeout(1200);

  await ctx.close();
  await browser.close();
  console.log('[web] PAIR COMPLETE');
  process.exit(0);
})().catch((e) => { console.error('[web] FAILED:', String(e).slice(0, 300)); process.exit(1); });
