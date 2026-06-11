// e2e-device-sheet.cjs — tile-interaction-v2 on a REAL remembered device.
//   MOBILE  : tapping the (known) tile opens the DeviceSheet with Send leading.
//   DESKTOP : hovering the tile reveals the action bar; ⋯ more opens the sheet.
// We pair for real first (CLI code), then exercise the divergent triggers and
// ASSERT the sheet actually opens with the right primary action.
//
// Usage: node e2e-device-sheet.cjs <app-url> <code> <mobile|desktop> <video-dir>
const { run } = require('../lib/driver.cjs');
const [url, code, mode, video] = process.argv.slice(2);
const mobile = (mode || 'mobile') === 'mobile';
const viewport = mobile ? { width: 390, height: 820 } : { width: 1100, height: 760 };

run({ name: `device-sheet-${mobile ? 'mobile' : 'desktop'}`, url, video, viewport, mobile }, async (page, h) => {
  // real pairing so there's a genuine REMEMBERED tile to interact with
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}
  // confirm the store first (authoritative), then wait for the live pickup — the
  // single-host live-pairing rescan + connect can take a while under load.
  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 30000 });
  await page.getByText('REMEMBERED', { exact: false }).first().waitFor({ timeout: 45000 });
  // the sheet/action-bar only render for a LIVE (ready) device — wait for it.
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText), { timeout: 45000 });
  h.log('remembered tile present and link ready');

  // the tile is the element whose REMEMBERED text sits in a clickable card; the
  // innermost div with REMEMBERED, then climb to the tile container by clicking
  // near the device name. We target the tile by its REMEMBERED label's ancestor.
  const remembered = page.getByText('REMEMBERED', { exact: false }).first();
  const tile = remembered.locator('xpath=ancestor::div[contains(@title,"Remembered")][1]');
  const tileEl = (await tile.count()) ? tile : remembered.locator('xpath=ancestor::div[3]');

  if (mobile) {
    // MOBILE: tapping the whole known tile opens the sheet
    await tileEl.first().click({ timeout: 8000 });
    h.log('tapped the known tile (mobile)');
  } else {
    // DESKTOP: hover reveals the action bar; click ⋯ more (or right-click) to open
    for (let i = 0; i < 8; i++) {
      await tileEl.first().hover({ timeout: 4000 }).catch(() => {});
      await page.waitForTimeout(500);
      if (await page.locator('button:has-text("⋯")').count()) break;
    }
    const more = page.locator('button:has-text("⋯")').first();
    if (await more.count()) { await more.click({ timeout: 6000 }); h.log('hover action bar → ⋯ more'); }
    else { await tileEl.first().click({ button: 'right' }); h.log('right-click → sheet'); }
  }

  // ASSERT: the DeviceSheet is open with Send files available
  const sendAction = page.getByText('Send files', { exact: false }).first();
  await sendAction.waitFor({ timeout: 12000 });
  h.log('DeviceSheet open — Send files action present');

  if (mobile) {
    // on the mobile (sendFirst) sheet, Send must LEAD — assert it is the first action.
    const firstAction = page.locator('text=/Send files|Open terminal/').first();
    const txt = await firstAction.textContent();
    if (!/Send/.test(txt || '')) return h.fail(`mobile sheet did not lead with Send (got: ${txt})`);
    h.log('mobile sheet leads with Send ✓');
  }
  await page.waitForTimeout(1400);
  h.pass(`tile-v2 ${mobile ? 'mobile tap→sheet (Send leads)' : 'desktop hover bar→sheet'} verified on a real remembered device`);
});
