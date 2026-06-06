// Gate: CLI -> browser. A real (headless) Chromium tab running the production
// frontend receives a file offered by the CLI. Usage:
//   node browser-receiver.js <app-url>
const { chromium } = require('playwright');

(async () => {
  const url = process.argv[2] || 'http://127.0.0.1:8077/';
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));

  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[pw] app loaded');

  const accept = page.getByText('accept', { exact: true }).first();
  await accept.waitFor({ timeout: 90000 });
  console.log('[pw] offer visible, clicking accept');
  await accept.click();

  await page.getByText('save', { exact: true }).first().waitFor({ timeout: 120000 });
  console.log('[pw] RECEIVE COMPLETE in browser');

  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 300));
  process.exit(1);
});
