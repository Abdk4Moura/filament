// journey-send-bigfile.cjs — HERO JOURNEY (Maya, café→home), browser leg.
//
// Maya's "home desktop" is a REAL filament `up` peer (paired/remembered). The
// browser (her laptop) DRAGS a multi-MB file onto its tile and it transfers
// byte-correct over real WebRTC. This driver is the user-visible half: it pairs
// for real (CLI mints a PAKE code), waits for the tile to go LIVE/ready, then
// performs a REAL drag-and-drop onto the tile (a synthetic `drop` carrying a
// genuine DataTransfer file — the same code path as a human dragging from
// Finder), and ASSERTS the app reports the transfer complete.
//
// The byte-correct arrival is asserted on the SHELL side by the suite (it
// sha256s the CLI `up` peer's drop dir). The café-wifi auto-heal (the P0/P1
// resilience) is proven on the direct-QUIC leg by the suite's freeze gate; this
// reel is the ergonomics — "paired once · 1 drag · it just lands."
//
// Usage: node journey-send-bigfile.cjs <app-url> <code> <file-path> <video-dir>
const { run } = require('../lib/driver.cjs');
const path = require('path');
const fs = require('fs');
const [url, code, filePath, video] = process.argv.slice(2);
const fileName = path.basename(filePath);

run({ name: 'maya-send-big-file', url, video, viewport: { width: 1180, height: 760 } }, async (page, h) => {
  // 1) real pairing: the home-desktop CLI peer minted `code`; Maya types it in.
  h.log('Maya pairs her home desktop (real PAKE code):', code);
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}

  // store is authoritative proof of pairing; then wait for the LIVE tile.
  await page.waitForFunction(() => {
    try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').length > 0 } catch { return false }
  }, { timeout: 30000 });
  h.log('home desktop remembered — waiting for the live link');
  // the drop only sends when the tile is ready (onDrop is gated on `ready`).
  await page.getByText('REMEMBERED', { exact: false }).first().waitFor({ timeout: 45000 });
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText), { timeout: 45000 });
  // locate the live tile via the REMEMBERED badge's ancestor (proven device-sheet path).
  const remembered = page.getByText('REMEMBERED', { exact: false }).first();
  const tileByTitle = remembered.locator('xpath=ancestor::div[contains(@title,"Remembered")][1]');
  const tile = (await tileByTitle.count()) ? tileByTitle.first() : page.locator('[data-testid="peer-tile"]').first();
  await tile.waitFor({ timeout: 15000 });
  await page.waitForTimeout(800);
  h.log('home desktop tile is LIVE — performing the drag-and-drop');

  // 2) the REAL gesture: build a genuine DataTransfer with the file's bytes and
  //    dispatch dragover→drop on the tile (the exact path PeerTile.onDrop runs;
  //    a human dragging from the file manager produces the same event).
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
  h.log('dropped', fileName, '(' + bytes.length + ' bytes) onto the home-desktop tile');

  // 3) ASSERT the app shows the transfer reaching complete (UI truth).
  await page.waitForFunction(() => /\bcomplete\b/i.test(document.body.innerText), { timeout: 120000 });
  h.log('the app reports the transfer COMPLETE');
  await page.waitForTimeout(1400);
  // ERGONOMICS marker emitted in the result detail (rendered into caption + reel).
  h.pass(`ERGO[paired once · 1 drag · it just lands] — dragged ${fileName} (${bytes.length}B) onto the home-desktop tile; app reports complete (byte-correctness asserted on the peer's drop dir; café-wifi auto-heal proven on the freeze gate)`);
});
