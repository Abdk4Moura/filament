#!/usr/bin/env python3
"""update_gallery.py — rebuild gallery/index.html + gallery/reels.html from the
pipeline's results + recorded mp4 reels.

Usage: update_gallery.py <results.txt> <gallery-dir>

results.txt lines: "RESULT <id> PASS|FAIL <detail>".
Reels are <gallery-dir>/reel-*.mp4 (one per recorded web case). Captions are
on-brand (dark/mono) and describe the REAL flow each reel shows.
"""
import os, re, sys, json, glob

RESULTS = sys.argv[1] if len(sys.argv) > 1 else None
GAL = sys.argv[2] if len(sys.argv) > 2 else "gallery"

# id -> (tag, title, caption) for the e2e cases (REAL app + REAL peers).
META = {
    "pair-device": ("pairing", "Pair → device appears",
        "A real CLI peer mints a PAKE code; the browser types it into the real pair box. The device is stored and a REMEMBERED tile appears — key never crosses the server."),
    "web-shell": ("web-shell", "Web-shell over the data channel",
        "Pair a real `up --shell` peer, open its terminal (›_), type a command, and watch the output stream back through the WebRTC data channel — a real PTY."),
    "device-sheet-mobile": ("tile-v2", "Mobile: tap tile → sheet (Send first)",
        "tile-interaction-v2: tapping a remembered tile on a phone opens the DeviceSheet with Send leading."),
    "device-sheet-desktop": ("tile-v2", "Desktop: hover action bar → sheet",
        "tile-interaction-v2: hovering a remembered tile reveals the action bar; ⋯ more opens the same DeviceSheet."),
    "sessions-dock": ("sessions", "Sessions dock: switch / background / close",
        "Open a real terminal, background it (the PTY and scrollback survive), reopen via its chip, and close it — the session dock against a live shell peer."),
    "cmd-k": ("palette", "⌘K command palette",
        "Open the real command palette, filter, and run the open-terminal action against a paired shell device."),
    "pwa-update": ("pwa", "PWA update — two builds",
        "Build A is serving; build B is deployed (a fresh /sw.js). The running service worker discovers the update — the 'New version available' nudge or a controllerchange takes over."),
}
ORDER = list(META.keys())


def load_results(path):
    res = {}
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"RESULT (\S+) (PASS|FAIL) ?(.*)", line.strip())
            if m:
                res[m.group(1)] = {"verdict": m.group(2), "detail": m.group(3)}
    return res


def reel_for(cid):
    # reels are named reel-<id>.mp4 (see pipeline finalize_reel)
    cands = [f"reel-{cid}.mp4", f"reel-{cid.replace('device-sheet-','device-sheet-')}.mp4"]
    # web-shell uses reel-webshell, pair-device uses reel-pair-device etc.
    alias = {"web-shell": "reel-webshell.mp4", "cmd-k": "reel-cmd-k.mp4"}
    cands.insert(0, alias.get(cid, f"reel-{cid}.mp4"))
    for c in cands:
        if os.path.exists(os.path.join(GAL, c)):
            return c
    return None


HEAD = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root{{color-scheme:dark}} *{{box-sizing:border-box}}
  body{{background:#0B0D0F;color:#D9DEE3;font:15px/1.5 ui-monospace,'JetBrains Mono',Menlo,monospace;margin:0;padding:26px}}
  h1{{font-size:21px;margin:0 0 4px;letter-spacing:.01em}}
  .sub{{color:#6E7681;margin:0 0 18px;font-size:13px}}
  .summary{{margin:10px 0 24px;font-size:13px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(480px,100%),1fr));gap:18px}}
  .card{{background:#0F1113;border:1px solid #1E2227;border-radius:8px;padding:14px;min-width:0}}
  .hd{{display:flex;justify-content:space-between;align-items:center;gap:8px}}
  .tag{{font-size:11px;color:#7CF6C8;border:1px solid #7CF6C855;padding:2px 8px;border-radius:9px;letter-spacing:.04em}}
  .badge{{color:#0B0D0F;font-size:11px;font-weight:700;padding:2px 9px;border-radius:9px}}
  h2{{font-size:15px;margin:9px 0 4px}}
  .cap{{color:#8A929B;font-size:12.5px;margin:0 0 10px}}
  .detail{{color:#5A626B;font-size:11.5px;margin:8px 0 0;overflow-wrap:anywhere}}
  video,img{{width:100%;height:auto;border-radius:6px;background:#000;border:1px solid #1E2227}}
  .nomedia{{height:120px;display:flex;align-items:center;justify-content:center;color:#444;border:1px dashed #1E2227;border-radius:6px;font-size:12px}}
  a{{color:#7CF6C8}}
</style></head><body>
<h1>{title}</h1>
<p class="sub">{sub}</p>"""


def main():
    res = load_results(RESULTS)
    os.makedirs(GAL, exist_ok=True)
    badge = {"PASS": "#7CF6C8", "FAIL": "#F26D6D"}

    # ----- reels.html: the recorded REAL-flow reels -----
    cards = []
    for cid in ORDER:
        tag, title, cap = META[cid]
        r = res.get(cid)
        reel = reel_for(cid)
        if reel:
            media = f'<video controls preload="metadata" src="{reel}"></video>'
        else:
            media = '<div class="nomedia">no reel (case failed or not recorded)</div>'
        vb = ""
        if r:
            col = badge.get(r["verdict"], "#888")
            vb = f'<span class="badge" style="background:{col}">{r["verdict"]}</span>'
        det = (r or {}).get("detail", "")
        cards.append(f"""
  <section class="card">
    <div class="hd"><span class="tag">{tag}</span>{vb}</div>
    <h2>{title}</h2><p class="cap">{cap}</p>
    {media}
    <p class="detail">{det}</p>
  </section>""")
    sub = "Live Playwright recordings driving the REAL app against REAL filament peers — real PAKE pairing, real PTYs, real WebRTC. webm→mp4, GPU-aware encode. <a href='./index.html'>← results</a>"
    html = HEAD.format(title="Filament — e2e reels (real peers)", sub=sub)
    html += f'\n<div class="grid">{"".join(cards)}</div>\n</body></html>'
    open(os.path.join(GAL, "reels.html"), "w").write(html)

    # ----- index.html: all case verdicts (web + cli + runner) -----
    npass = sum(1 for v in res.values() if v["verdict"] == "PASS")
    nfail = sum(1 for v in res.values() if v["verdict"] == "FAIL")
    rows = []
    for cid, r in sorted(res.items()):
        col = badge.get(r["verdict"], "#888")
        tag = META.get(cid, ("", "", ""))[0] or ("cli" if cid.startswith("cli-") else "runner" if "runner" in cid else "case")
        title = META.get(cid, ("", cid, ""))[1] or cid
        rows.append(f"""
  <section class="card">
    <div class="hd"><span class="tag">{tag}</span><span class="badge" style="background:{col}">{r['verdict']}</span></div>
    <h2>{cid}</h2><p class="cap">{title}</p>
    <p class="detail">{r['detail']}</p>
  </section>""")
    sub = f"<b style='color:#7CF6C8'>{npass} PASS</b> &nbsp; <b style='color:#F26D6D'>{nfail} FAIL</b> &nbsp;·&nbsp; real-app + real-peer e2e + live reels. <a href='./reels.html'>reels →</a>"
    html = HEAD.format(title="Filament — e2e pipeline results", sub=sub)
    html += f'\n<div class="grid">{"".join(rows)}</div>\n</body></html>'
    open(os.path.join(GAL, "index.html"), "w").write(html)

    # machine-readable too
    json.dump(res, open(os.path.join(GAL, "results.json"), "w"), indent=2)
    print(f"[gallery] {npass} pass, {nfail} fail -> {GAL}/index.html + reels.html")


if __name__ == "__main__":
    main()
