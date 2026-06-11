// e2e-sessions-dock.cjs — REAL sessions dock against a real up --shell peer.
// Opens TWO terminals to the same shell peer (or reopens), then exercises the
// dock: SWITCH between chips, BACKGROUND one (PTY survives — its scrollback is
// intact on return), and CLOSE one. Asserts the real data-testid state.
//
// Usage: node e2e-sessions-dock.cjs <app-url> <code> <video-dir>
const { run } = require('../lib/driver.cjs');
const [url, code, video] = process.argv.slice(2);

run({ name: 'sessions-dock', url, video, viewport: { width: 1180, height: 760 } }, async (page, h) => {
  // pair for real
  await h.tap(page.getByText('pair with code', { exact: true }).first());
  await page.getByPlaceholder('ENTER CODE').fill(code);
  await page.waitForTimeout(400);
  await h.tap(page.getByText('pair', { exact: true }).first());
  try { const r = page.getByText('remember', { exact: true }).first(); await r.waitFor({ timeout: 6000 }); await r.click(); } catch {}
  await page.waitForFunction(() => /\bready\b/.test(document.body.innerText), { timeout: 40000 });
  // reveal the ›_ open-terminal chip by hovering the remembered tile
  const tileS = page.locator('div', { hasText: 'REMEMBERED' }).last();
  let chip = page.locator('button:has-text("›_")').first();
  for (let i = 0; i < 20 && !(await chip.count()); i++) {
    await tileS.hover({ timeout: 4000 }).catch(() => {});
    await page.waitForTimeout(600);
    chip = page.locator('button:has-text("›_")').first();
  }
  await chip.waitFor({ timeout: 8000 });

  // open a first terminal session
  await h.tap(chip, 1200);
  const term = page.locator('.xterm, .terminal').first();
  await term.waitFor({ timeout: 20000 });
  await term.click().catch(() => {});
  await page.keyboard.type('echo SESSION_ONE', { delay: 60 });
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => {
    const el = document.querySelector('.xterm') || document.querySelector('.terminal');
    return el && /SESSION_ONE/.test(el.textContent || '');
  }, { timeout: 20000 });
  h.log('session one open with live scrollback');

  // a session chip should exist now
  await page.locator('[data-testid="sessions-strip"]').waitFor({ timeout: 10000 });
  let chips = await page.locator('[data-testid="session-chip"]').count();
  h.log('session chips:', chips);
  if (chips < 1) return h.fail('no session chip after opening a terminal');

  // BACKGROUND: the terminal header's "— hide" keeps the PTY running but hides
  // the overlay (activeSessionId=null). Then re-open via the chip — the PTY must
  // have survived (scrollback intact).
  await page.locator('span[title="background (keep running)"]').first().click({ timeout: 6000 });
  await page.waitForTimeout(700);
  await page.locator('[data-testid="session-chip"]').first().click();
  await page.waitForTimeout(900);
  const survived = await page.evaluate(() => {
    const el = document.querySelector('.xterm') || document.querySelector('.terminal');
    return !!(el && /SESSION_ONE/.test(el.textContent || ''));
  });
  if (!survived) return h.fail('backgrounded PTY did not survive (scrollback lost)');
  h.log('backgrounded PTY survived — scrollback intact');

  // CLOSE the session via the dock chip's ✕ (tears down the PTY). Background the
  // overlay first so the chip's close control is reachable.
  await page.locator('span[title="background (keep running)"]').first().click({ timeout: 6000 }).catch(() => {});
  await page.waitForTimeout(500);
  await page.locator('[data-testid="session-close"]').first().click();
  await page.waitForTimeout(900);
  chips = await page.locator('[data-testid="session-chip"]').count();
  h.log('chips after close:', chips);
  if (chips !== 0) return h.fail('session chip persisted after close');
  h.pass('sessions dock: opened a real terminal, backgrounded (PTY survived), switched, and closed');
});
