// journey-phone-to-laptop.cjs — Maya journey 2: a file goes phone → laptop.
//
// Maya's "phone" is a REAL filament peer (a CLI `send` in the shared auto-room).
// Her laptop is the browser. The phone pushes a file; the laptop shows the
// incoming offer, Maya taps to receive, and it ARRIVES (the save/download
// affordance appears, byte-for-byte the file the phone sent). This is the
// one-tap "send from my phone, it's on my laptop" path — no codes to retype.
//
// The CLI `send` peer is started by the suite (it shares the room); this driver
// is the laptop half: open the app, wait for the offer, accept, assert arrival.
//
// Usage: node journey-phone-to-laptop.cjs <app-url> <expected-name> <video-dir>
const { run } = require('../lib/driver.cjs');
const [url, expectName, video] = process.argv.slice(2);

run({ name: 'maya-phone-to-laptop', url, video, viewport: { width: 1100, height: 720 } }, async (page, h) => {
  h.log('Maya opens her laptop — waiting for the file her phone is sending');

  // the phone (CLI sender) offers into the shared auto-room; the laptop shows an
  // accept affordance. Tap it (the one gesture) — then the file downloads.
  const accept = page.getByText('accept', { exact: true }).first();
  await accept.waitFor({ timeout: 90000 });
  h.log('phone\'s file offer arrived on the laptop — accepting (one tap)');
  await page.waitForTimeout(600);
  await accept.click();

  // ASSERT arrival: the save/download affordance shows (transfer reached the
  // laptop, byte-complete — the suite also sha256-verifies the saved bytes).
  await page.getByText('save', { exact: true }).first().waitFor({ timeout: 90000 });
  h.log('file is on the laptop — save/download ready');
  // best-effort: the offered name is visible in the transfer row
  let named = false;
  try { await page.getByText(expectName, { exact: false }).first().waitFor({ timeout: 4000 }); named = true; } catch {}
  await page.waitForTimeout(1300);
  h.pass(`ERGO[no code · 1 tap · it's on the laptop] — phone→laptop transfer arrived (save ready${named ? `, name "${expectName}" shown` : ''})`);
});
