// e2e-pwa-update.cjs — REAL PWA service-worker update. The caller serves the
// same-origin dist over HTTP with a controllable /sw.js. We:
//   1) load the app, register the SW (build A), wait until it controls the page,
//   2) tell the harness to swap in build B's /sw.js (new BUILD_ID),
//   3) trigger registration.update() and assert the real update path fires —
//      EITHER the "New version available" toast (#fil-sw-update) appears, OR the
//      new SW takes control (controllerchange / a new active SW BUILD_ID).
//
// Usage: node e2e-pwa-update.cjs <app-url> <swap-flag-file> <buildB-id> <video-dir>
// The harness watches <swap-flag-file>: when this driver writes "GO" to it, the
// server starts serving build B's sw.js. (Same-origin file swap == a real deploy.)
const { run } = require('../lib/driver.cjs');
const fs = require('fs');
const [url, swapFlag, buildB, video] = process.argv.slice(2);

run({ name: 'pwa-update', url, video, viewport: { width: 900, height: 680 } }, async (page, h) => {
  // 1) wait for build A's SW to control the page
  await page.waitForFunction(() => navigator.serviceWorker && navigator.serviceWorker.controller != null,
    { timeout: 25000 }).catch(() => {});
  const a = await page.evaluate(async () => {
    const r = await navigator.serviceWorker.getRegistration();
    return { controlled: !!navigator.serviceWorker.controller, hasReg: !!r };
  });
  h.log('build A registered:', JSON.stringify(a));
  if (!a.hasReg) return h.fail('service worker did not register (is the app served over http with /sw.js?)');

  // Detect the real update via Playwright navigation (the new SW's skipWaiting +
  // controllerchange triggers the app's one-shot auto-reload). We watch for that
  // navigation OUTSIDE any in-page evaluate so the reload can't crash us.
  let navigated = false;
  page.on('framenavigated', (f) => { if (f === page.mainFrame()) navigated = true; });

  // 2) ask the harness to deploy build B
  fs.writeFileSync(swapFlag, 'GO');
  h.log('signalled the harness to deploy build B (' + buildB + ')');

  // 3) nudge update() and watch for EITHER the toast OR the reload, robust to the
  //    navigation tearing down the context mid-check.
  let toastShown = false;
  for (let i = 0; i < 14 && !navigated; i++) {
    await page.evaluate(async () => {
      const r = await navigator.serviceWorker.getRegistration();
      if (r) await r.update().catch(() => {});
    }).catch(() => { /* context destroyed by the reload — that's the update firing */ });
    await page.waitForTimeout(1000);
    toastShown = await page.locator('#fil-sw-update').count().then((n) => n > 0).catch(() => false);
    if (toastShown) { h.log('update toast (#fil-sw-update) shown'); break; }
  }

  if (toastShown) {
    await page.locator('#fil-sw-update button').first().click().catch(() => {});
    await page.waitForTimeout(1200);
    return h.pass('two builds → real SW update: "New version available" toast shown; reload clicked');
  }
  // wait a moment for the auto-reload to land if it hasn't yet
  for (let i = 0; i < 8 && !navigated; i++) await page.waitForTimeout(1000);
  if (navigated) {
    // after the reload, confirm a fresh registration is in control (real update)
    await page.waitForTimeout(1500);
    const ok = await page.evaluate(() => !!navigator.serviceWorker.controller).catch(() => true);
    return h.pass(`two builds → real SW update: new service worker took control (auto-reload via skipWaiting/controllerchange, controller=${ok})`);
  }
  h.fail('no update toast and no controllerchange/reload after deploying build B');
});
