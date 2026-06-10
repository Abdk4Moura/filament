// Scenario 09 browser half: the web app, sharing the auto-room with a CLI
// `recv`, picks a file and sends it to the CLI peer tile. Records webm.
// Usage:  node send-to-cli.js <app-url> <file> <video-dir>
const { chromium } = require('playwright');
const MDNS_OFF = ['--disable-features=WebRtcHideLocalIpsWithMdns',
                  '--force-fieldtrials=WebRTC-Mdns/Disabled/'];

(async () => {
  const [url, file, videoDir] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true,
    args: ['--no-sandbox','--disable-dev-shm-usage', ...MDNS_OFF] });
  const ctx = await browser.newContext({
    recordVideo: { dir: videoDir, size: { width: 900, height: 620 } },
    viewport: { width: 900, height: 620 },
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));
  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[web] app loaded — waiting for the CLI peer to appear');

  const input = page.locator('input[type=file]').first();
  await input.waitFor({ state: 'attached', timeout: 60000 });
  console.log('[web] CLI peer tile present — sending file');
  await page.waitForTimeout(600);
  await input.setInputFiles(file);

  await page.getByText('complete', { exact: true }).first().waitFor({ timeout: 120000 });
  console.log('[web] SEND COMPLETE (browser reports complete)');
  await page.waitForTimeout(1200);

  await ctx.close();
  await browser.close();
  console.log('[web] SEND-TO-CLI COMPLETE');
  process.exit(0);
})().catch((e) => { console.error('[web] FAILED:', String(e).slice(0, 300)); process.exit(1); });
