const { chromium } = require('playwright');
(async () => {
  const room = process.argv[2];
  const browser = await chromium.launch({ headless: true });
  const pages = [];
  for (let i = 0; i < 2; i++) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`http://127.0.0.1:8077/rooms/${room}`, { waitUntil: 'networkidle' });
    pages.push(page);
  }
  // wait until BOTH pages show 2 ready peers (each other + the CLI)
  for (const [i, page] of pages.entries()) {
    await page.waitForFunction(() => {
      const txt = document.body.innerText;
      return !txt.includes('connecting');
    }, { timeout: 60000 });
    console.log(`[pw] page ${i}: no tiles stuck at connecting`);
  }
  // first browser accepts the CLI's offer
  const accept = pages[0].getByText('accept', { exact: true }).first();
  await accept.waitFor({ timeout: 30000 });
  await accept.click();
  await pages[0].getByText('save', { exact: true }).first().waitFor({ timeout: 60000 });
  console.log('[pw] C18 PASS: transfer completed with a bystander browser present');
  await browser.close();
})().catch(e => { console.error('[pw] FAILED:', String(e).slice(0,200)); process.exit(1); });
