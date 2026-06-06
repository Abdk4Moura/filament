// Gates C1 + C9: browser -> CLI, twice, human-paced. A real Chromium tab
// running the production frontend sends file A, waits, then sends file B
// several seconds later. Verifies (a) the CLI accepts browser-framed chunks
// (C1) and (b) the CLI receiver stays alive between human-paced sends (C9).
// The CLI side does the byte-level assertions; this script just drives.
// Usage: node browser-sender.js <app-url> <fileA> <fileB>
const { chromium } = require('playwright');

(async () => {
  const [url, fileA, fileB] = process.argv.slice(2);
  if (!url || !fileA || !fileB) throw new Error('usage: browser-sender.js <url> <fileA> <fileB>');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));

  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[pw] app loaded');

  // Wait for the CLI peer tile (it renders a hidden per-peer file input).
  const input = page.locator('input[type=file]').first();
  await input.waitFor({ state: 'attached', timeout: 60000 });
  console.log('[pw] peer tile present');

  await input.setInputFiles(fileA);
  console.log('[pw] sent file A');
  // First transfer reaches 'complete' in the transfers panel.
  await page.getByText('complete', { exact: true }).first().waitFor({ timeout: 120000 });
  console.log('[pw] file A complete in browser');

  // Human-paced gap — longer than any receiver idle-exit heuristic.
  await page.waitForTimeout(5000);

  await input.setInputFiles(fileB);
  console.log('[pw] sent file B');
  await page.getByText('complete', { exact: true }).nth(1).waitFor({ timeout: 120000 });
  console.log('[pw] file B complete in browser');

  await browser.close(); // peer-left lets the CLI receiver finish cleanly
  console.log('[pw] BROWSER SENDER DONE');
  process.exit(0);
})().catch((e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 300));
  process.exit(1);
});
