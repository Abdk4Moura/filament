// journey-drag-build.cjs — Sam journey: drag a build artifact onto the server.
//
// Sam just built something; he drags the artifact straight onto his home
// server's tile in the browser and it lands there (real WebRTC transfer to the
// server's `up --dir`). The "ship the build to the box" gesture, one drag.
//
// Usage: node journey-drag-build.cjs <app-url> <code> <file-path> <video-dir>
const { run } = require('../lib/driver.cjs');
const path = require('path');
const fs = require('fs');
const [url, code, filePath, video] = process.argv.slice(2);
const fileName = path.basename(filePath);

run({ name: 'sam-drag-build', url, video, viewport: { width: 1180, height: 760 } }, async (page, h) => {
  // pair the server once (real PAKE)
  h.log('Sam pairs his home server (real code):', code);
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}
  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 30000 });
  // wait for the LIVE remembered tile exactly as the proven device-sheet driver:
  // a REMEMBERED badge in the tile + the link reaching ready.
  await page.getByText('REMEMBERED', { exact: false }).first().waitFor({ timeout: 45000 });
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText), { timeout: 45000 });
  // locate the tile via the REMEMBERED badge's ancestor (the clickable card).
  const remembered = page.getByText('REMEMBERED', { exact: false }).first();
  const tileByTitle = remembered.locator('xpath=ancestor::div[contains(@title,"Remembered")][1]');
  const tile = (await tileByTitle.count()) ? tileByTitle.first() : page.locator('[data-testid="peer-tile"]').first();
  await tile.waitFor({ timeout: 15000 });
  await page.waitForTimeout(800);
  h.log('home server tile LIVE — dragging the build artifact on');

  const bytes = Array.from(fs.readFileSync(filePath));
  await tile.scrollIntoViewIfNeeded().catch(() => {});
  await tile.hover().catch(() => {});
  await page.waitForTimeout(300);
  await tile.evaluate(async (el, { name, data }) => {
    const dt = new DataTransfer();
    const file = new File([new Uint8Array(data)], name, { type: 'application/octet-stream' });
    dt.items.add(file);
    const rect = el.getBoundingClientRect();
    const at = { clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2 };
    const fire = (type) => el.dispatchEvent(new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt, ...at }));
    fire('dragenter'); fire('dragover');
    await new Promise((r) => setTimeout(r, 250));
    fire('drop');
  }, { name: fileName, data: bytes });
  h.log('dropped', fileName, '(' + bytes.length + ' bytes) onto the server tile');

  await page.waitForFunction(() => /\bcomplete\b/i.test(document.body.innerText), { timeout: 120000 });
  h.log('the app reports the build artifact landed (complete)');
  await page.waitForTimeout(1300);
  h.pass(`ERGO[1 drag · it's on the box] — dragged build artifact ${fileName} (${bytes.length}B) onto the home server tile; app reports complete (byte-correctness asserted on the server's drop dir)`);
});
