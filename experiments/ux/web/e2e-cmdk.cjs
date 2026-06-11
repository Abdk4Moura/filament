// e2e-cmdk.cjs — REAL ⌘K command palette. Pairs a shell peer, opens the palette
// (cmd-open / ⌘K), types to filter, and runs the "open a terminal" item — then
// asserts a real terminal session opened. Drives the genuine palette, no mock.
//
// Usage: node e2e-cmdk.cjs <app-url> <code> <video-dir>
const { run } = require('../lib/driver.cjs');
const [url, code, video] = process.argv.slice(2);

run({ name: 'cmd-k', url, video, viewport: { width: 1180, height: 760 } }, async (page, h) => {
  // pair for real so the palette has a shell device to act on
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText), { timeout: 40000 });
  // the palette's "Open terminal" item needs ready && known && p.shell. Confirm
  // the shell capability has actually propagated (the ›_ chip appears on hover)
  // BEFORE opening the palette, so the open-terminal item is guaranteed present.
  const tileC = page.locator('div', { hasText: 'REMEMBERED' }).last();
  for (let i = 0; i < 25 && !(await page.locator('button:has-text("›_")').count()); i++) {
    await tileC.hover({ timeout: 4000 }).catch(() => {});
    await page.waitForTimeout(600);
  }
  await page.locator('button:has-text("›_")').first().waitFor({ timeout: 8000 });
  h.log('shell device ready + shell capability confirmed');

  // open the palette, filter, and find the open-terminal item — retry the
  // open/filter a few times in case the palette item list is still settling.
  const input = page.locator('[data-testid="cmd-input"]');
  const items = page.locator('[data-testid="cmd-item"]');
  let n = 0;
  for (let attempt = 0; attempt < 5; attempt++) {
    await page.keyboard.press('Control+k');
    if (!(await page.locator('[data-testid="cmd-palette"]').count())) {
      await page.locator('[data-testid="cmd-open"]').first().click().catch(() => {});
    }
    await page.locator('[data-testid="cmd-palette"]').waitFor({ timeout: 8000 });
    await input.fill('terminal');
    await page.waitForTimeout(600);
    n = await items.count();
    h.log(`palette open (attempt ${attempt + 1}) — items matching "terminal": ${n}`);
    if (n >= 1) break;
    await page.keyboard.press('Escape').catch(() => {});
    await page.waitForTimeout(800);
  }
  if (n < 1) return h.fail('palette had no items matching "terminal"');

  // run the first matching item (open a terminal)
  await items.first().click();
  await page.waitForTimeout(900);

  // ASSERT: a terminal session opened (xterm mounted OR a session chip appeared)
  const opened = await page.evaluate(() => {
    const term = document.querySelector('.xterm') || document.querySelector('.terminal');
    const chip = document.querySelector('[data-testid="session-chip"]');
    return !!(term || chip);
  });
  if (!opened) return h.fail('palette action did not open a terminal session');
  h.log('palette opened a real terminal session');
  await page.waitForTimeout(1200);
  h.pass('⌘K palette: opened, filtered, and ran the open-terminal action against a real shell device');
});
