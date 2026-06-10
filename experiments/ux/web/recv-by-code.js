// Scenario 08 browser half: CLI -> web. The web app, sharing the auto-room with
// the CLI sender (both on 127.0.0.1), receives the offered file and reaches the
// 'save' affordance (download ready). Records a webm video of the tab.
//
// NOTE on the rig: chromium masks loopback host ICE candidates behind mDNS
// `.local` names the CLI's WebRTC stack cannot resolve, so single-host
// CLI<->browser ICE WEDGES unless we disable that masking. The two launch flags
// below emit real 127.0.0.1 candidates and make ICE complete. (In production,
// browser<->browser uses mDNS fine and CLI<->browser is cross-host with real
// IPs, so this is purely a single-host test accommodation.)
// Usage:  node recv-by-code.js <app-url> <unused-code> <video-dir>
const { chromium } = require('playwright');
const MDNS_OFF = ['--disable-features=WebRtcHideLocalIpsWithMdns',
                  '--force-fieldtrials=WebRTC-Mdns/Disabled/'];

(async () => {
  const [url, _code, videoDir] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true,
    args: ['--no-sandbox','--disable-dev-shm-usage', ...MDNS_OFF] });
  const ctx = await browser.newContext({
    recordVideo: { dir: videoDir, size: { width: 900, height: 620 } },
    viewport: { width: 900, height: 620 },
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));
  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[web] app loaded — joined the auto-room, waiting for the CLI offer');

  const accept = page.getByText('accept', { exact: true }).first();
  await accept.waitFor({ timeout: 60000 });
  console.log('[web] file offer arrived — accepting');
  await page.waitForTimeout(700);
  await accept.click();

  await page.getByText('save', { exact: true }).first().waitFor({ timeout: 60000 });
  console.log('[web] DOWNLOAD READY (save affordance shown)');
  await page.waitForTimeout(1400);

  await ctx.close(); // flush video
  await browser.close();
  console.log('[web] RECV COMPLETE');
  process.exit(0);
})().catch((e) => { console.error('[web] FAILED:', String(e).slice(0, 300)); process.exit(1); });
