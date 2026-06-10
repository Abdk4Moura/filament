#!/usr/bin/env python3
"""Build gallery/index.html + gallery/results.json from .work/results-*.txt.

Each results-<id>.txt holds a single line:  RESULT <id> PASS|FAIL <detail>
A static map provides the caption + flow class (cli<->cli / cli<->web).
"""
import glob, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, ".work")
GAL = os.path.join(HERE, "gallery")

META = {
    "01": ("cli↔cli", "Pair two devices", "A mints a PAKE code, B claims it; both derive the same channel — no key crosses the server."),
    "02": ("cli↔cli", "Devices: list / rename / forget", "And the regression guard: forgetting one device must NOT wipe another device's granted shell cap."),
    "03": ("cli↔cli", "Send with a one-time code", "Sender mints a speakable code; the receiver claims it and the bytes land, sha256-verified end-to-end."),
    "04": ("cli↔cli", "Send --to a known device", "No code: a remembered device, identity proof-verified and auto-accepted; bytes sha256-verified."),
    "05": ("cli↔cli", "Always-on receiver: up / status / down", "Bring up a trusted-only drop target, send into it, check status, stop it; bytes sha256-verified."),
    "06": ("cli↔cli", "Grant shell + ssh over the tunnel", "Deny-by-default consent; then `filament ssh peer -- echo OK` runs over the data channel."),
    "07": ("cli↔cli", "Introduce two devices", "A hub that knows both vouches them to each other with a fresh mutual secret."),
    "08": ("cli↔web", "CLI sends → the web app receives", "The browser (local frontend) accepts the offered file and reaches the download affordance."),
    "09": ("cli↔web", "The web app sends → CLI recv", "Browser picks a file and sends it; the CLI receiver writes it, sha256-verified (authoritative no-recorder verify pass). The GIF is a best-effort visual; single-host browser→CLI WebRTC can't complete while the webm recorder runs — see README."),
    "10": ("cli↔web", "Pair the web app with the CLI", "CLI mints a PAKE code; the browser claims it and stores the device (key never crosses the server)."),
}

def load_results():
    res = {}
    for f in sorted(glob.glob(os.path.join(WORK, "results-*.txt"))):
        line = open(f).read().strip()
        m = re.match(r"RESULT (\S+) (PASS|FAIL) ?(.*)", line)
        if m:
            res[m.group(1)] = {"verdict": m.group(2), "detail": m.group(3)}
    return res

def main():
    res = load_results()
    rows = []
    out = {}
    for sid, (flow, title, cap) in META.items():
        r = res.get(sid, {"verdict": "BLOCKED", "detail": "not recorded"})
        gif = f"{sid}.gif" if os.path.exists(os.path.join(GAL, f"{sid}.gif")) else None
        out[sid] = {"flow": flow, "title": title, "caption": cap, **r, "gif": gif}
        rows.append((sid, flow, title, cap, r["verdict"], r["detail"], gif))

    with open(os.path.join(GAL, "results.json"), "w") as f:
        json.dump(out, f, indent=2)

    npass = sum(1 for v in out.values() if v["verdict"] == "PASS")
    nfail = sum(1 for v in out.values() if v["verdict"] == "FAIL")
    nblock = sum(1 for v in out.values() if v["verdict"] == "BLOCKED")

    badge = {"PASS": "#1f9d55", "FAIL": "#c0392b", "BLOCKED": "#888"}
    cards = []
    for sid, flow, title, cap, verdict, detail, gif in rows:
        media = (f'<img loading="lazy" src="{gif}" alt="{title}">' if gif
                 else '<div class="nogif">no recording</div>')
        cards.append(f"""
      <section class="card">
        <div class="hd"><span class="flow">{flow}</span>
          <span class="badge" style="background:{badge[verdict]}">{verdict}</span></div>
        <h2>{sid} · {title}</h2>
        <p class="cap">{cap}</p>
        {media}
        <p class="detail">{detail}</p>
      </section>""")

    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Filament CLI — UX flow gallery</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:32px; }}
  h1 {{ font-size:24px; margin:0 0 4px; }}
  .sub {{ color:#8b949e; margin:0 0 8px; }}
  .summary {{ margin:12px 0 28px; font-size:14px; }}
  .summary b {{ font-size:18px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(440px,1fr)); gap:20px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; }}
  .hd {{ display:flex; justify-content:space-between; align-items:center; }}
  .flow {{ font:12px monospace; color:#58a6ff; letter-spacing:.04em; }}
  .badge {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px; }}
  h2 {{ font-size:16px; margin:8px 0 4px; }}
  .cap {{ color:#8b949e; font-size:13px; margin:0 0 10px; }}
  .detail {{ color:#6e7681; font-size:12px; margin:8px 0 0; font-family:monospace; }}
  img {{ width:100%; border-radius:6px; border:1px solid #30363d; background:#000; }}
  .nogif {{ height:140px; display:flex; align-items:center; justify-content:center; color:#555; border:1px dashed #30363d; border-radius:6px; }}
</style></head><body>
  <h1>Filament CLI — UX flow gallery</h1>
  <p class="sub">Human-watchable recordings of each CLI UX flow (cli↔cli and cli↔web), driven against a local backend.</p>
  <p class="summary"><b style="color:#1f9d55">{npass} PASS</b> &nbsp; <b style="color:#c0392b">{nfail} FAIL</b> &nbsp; <b style="color:#888">{nblock} BLOCKED</b> &nbsp; / 10 scenarios</p>
  <div class="grid">{''.join(cards)}</div>
</body></html>"""
    with open(os.path.join(GAL, "index.html"), "w") as f:
        f.write(html)
    print(f"gallery: {npass} pass, {nfail} fail, {nblock} blocked")

if __name__ == "__main__":
    main()
