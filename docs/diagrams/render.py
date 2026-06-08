#!/usr/bin/env python3
"""Render Filament's transport matrix + session state machine as PNGs."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.lines import Line2D

BG = "#0d1117"; FG = "#e6edf3"; MUT = "#adbac7"
GREEN_F = "#13311f"; GREEN_E = "#2ea043"; GREEN_T = "#7ee787"
RED_F = "#3d1d1d"; RED_E = "#f85149"; RED_T = "#ffa198"
AMB_F = "#2d2410"; AMB_E = "#d29922"; AMB_T = "#e3b341"
BLU_F = "#1c2b3a"; BLU_E = "#1f6feb"; BLU_T = "#79c0ff"
GRY_F = "#21262d"; GRY_E = "#30363d"

def box(ax, x, y, w, h, text, fc=GRY_F, ec=GRY_E, tc=FG, fs=11, shape="round", lw=1.6):
    style = {"round": "round,pad=0.02,rounding_size=0.12", "oval": "round,pad=0.02,rounding_size=0.5",
             "sharp": "square,pad=0.02"}[shape]
    p = FancyBboxPatch((x-w/2, y-h/2), w, h, boxstyle=style, fc=fc, ec=ec, lw=lw, zorder=2)
    ax.add_patch(p)
    ax.text(x, y, text, ha="center", va="center", color=tc, fontsize=fs, zorder=3, family="DejaVu Sans")
    return (x, y, w, h)

def arrow(ax, a, b, label="", color=MUT, tc=MUT, style="-", rad=0.0, fs=9, lx=0.5):
    (x1,y1,w1,h1)=a; (x2,y2,w2,h2)=b
    # connect from edge centers, pick nearest vertical/horizontal
    dx, dy = x2-x1, y2-y1
    if abs(dy) >= abs(dx):
        sy = y1 + (h1/2 if dy>0 else -h1/2); ey = y2 + (-h2/2 if dy>0 else h2/2)
        sx, ex = x1, x2
    else:
        sx = x1 + (w1/2 if dx>0 else -w1/2); ex = x2 + (-w2/2 if dx>0 else w2/2)
        sy, ey = y1, y2
    ar = FancyArrowPatch((sx,sy),(ex,ey), arrowstyle="-|>", mutation_scale=14,
                         color=color, lw=1.6, ls=style, zorder=1,
                         connectionstyle=f"arc3,rad={rad}")
    ax.add_patch(ar)
    if label:
        mx, my = sx+(ex-sx)*lx, sy+(ey-sy)*lx
        ax.text(mx, my, label, ha="center", va="center", color=tc, fontsize=fs,
                family="DejaVu Sans", zorder=4,
                bbox=dict(boxstyle="round,pad=0.18", fc=BG, ec="none", alpha=0.85))

def newfig(w, h, title):
    fig, ax = plt.subplots(figsize=(w, h)); fig.patch.set_facecolor(BG); ax.set_facecolor(BG)
    ax.set_xlim(0,100); ax.set_ylim(0,100); ax.axis("off")
    ax.text(50, 97, title, ha="center", va="top", color=FG, fontsize=16, weight="bold", family="DejaVu Sans")
    return fig, ax

# ============================================================ 1. MATRIX
fig, ax = newfig(13, 8, "Filament — transport per client pair (who speaks what)")
ax.text(50, 92, "WebRTC is the browser's constraint, not the CLI's", ha="center", color=MUT, fontsize=11)

brow = box(ax, 22, 80, 30, 9, "BROWSER\nWebRTC only — sandboxed, no raw sockets", AMB_F, AMB_E, AMB_T, 10)
cli  = box(ax, 72, 80, 34, 9, "CLI / daemon\nraw TCP/QUIC  +  WebRTC (full stack)", GREEN_F, GREEN_E, GREEN_T, 10)

bb = box(ax, 18, 60, 24, 7, "browser ↔ browser", GRY_F, GRY_E, FG, 11, "oval")
bc = box(ax, 50, 60, 22, 7, "browser ↔ CLI", GRY_F, GRY_E, FG, 11, "oval")
cc = box(ax, 82, 60, 20, 7, "CLI ↔ CLI", GRY_F, GREEN_E, GREEN_T, 11, "oval")

wrtc = box(ax, 30, 36, 40, 11, "WEBRTC\nDataChannel / DTLS / SCTP\nICE = STUN + TURN relay", RED_F, RED_E, RED_T, 10)
dire = box(ax, 78, 36, 38, 11, "DIRECT  TCP now / QUIC next\nNoise handshake, pair-secret PSK\nno STUN · no TURN · no ICE", GREEN_F, GREEN_E, GREEN_T, 10)

arrow(ax, bb, wrtc, "forced", RED_E, RED_T, lx=0.55)
arrow(ax, bc, wrtc, "forced\n(browser end)", RED_E, RED_T, rad=0.1, lx=0.5)
arrow(ax, cc, dire, "preferred:\n1-RTT, no relay tax", GREEN_E, GREEN_T, lx=0.5)
arrow(ax, cc, wrtc, "fallback: both\nbehind symmetric NAT", AMB_E, AMB_T, style="--", rad=0.25, lx=0.42)

box(ax, 50, 13, 86, 12,
    "THE LIVE FAILURE (2026-06-08): two CLIs forced down the WebRTC branch; ICE cross-NAT never completed;\n"
    "creator watchdog'd 3×15s and quit; claimer orphaned (caught now as divergence D3). do-vm had a PUBLIC IP\n"
    "and no firewall — a direct TCP dial would have connected at once. WebRTC imposed browser-grade NAT\n"
    "traversal on a pair that did not need it.", "#161b22", RED_E, RED_T, 9.5)
fig.savefig("/root/.claude/jobs/330c2366/tmp/diagram-transport-matrix.png", dpi=160, facecolor=BG, bbox_inches="tight")
print("matrix done")

# ============================================================ 2. STATE MACHINE
fig, ax = newfig(15, 12, "Filament — the session state machine (every state a client can be in)")
ax.text(50, 94.5, "green = terminal-good   ·   red = divergence (tel-watch.py)   ·   amber = resilience overlay (legal)",
        ha="center", color=MUT, fontsize=10)

proc = box(ax, 50, 90, 16, 4.5, "process start", BLU_F, BLU_E, "white", 10, "oval")
conn = box(ax, 50, 82, 18, 5, "CONNECTING", GRY_F, GRY_E, FG, 11)
join = box(ax, 50, 73, 30, 6, "JOINED  (in a room)\n↺ sync heartbeat ≤35s", GRY_F, GRY_E, FG, 11)

wait = box(ax, 16, 62, 22, 6, "WAITING_CLAIM\n(code shown)", GRY_F, GRY_E, FG, 10)
subs = box(ax, 41, 62, 20, 6, "SUBSCRIBED\n(channels raised)", GRY_F, GRY_E, FG, 10)
lstn = box(ax, 64, 62, 20, 6, "LISTENING\n(recv / up)", GRY_F, GRY_E, FG, 10)

paired = box(ax, 41, 51, 26, 6, "PAIRED_ROOM\ntwo sids, one room · ≤30s", GRY_F, BLU_E, BLU_T, 10)
tport  = box(ax, 41, 41, 22, 6, "◆ TRANSPORT?", BLU_F, BLU_E, BLU_T, 11)
wrtc   = box(ax, 22, 31, 22, 6, "WEBRTC / ICE\nconnecting ≤25s", GRY_F, GRY_E, FG, 10)
dire   = box(ax, 60, 31, 22, 6, "DIRECT TCP/QUIC\n1-RTT dial", GRY_F, GREEN_E, GREEN_T, 10)

ready = box(ax, 41, 21, 18, 5, "CONNECTED", GREEN_F, GREEN_E, GREEN_T, 11)
xfer  = box(ax, 17, 12, 24, 6, "TRANSFER\noffered→…→complete", GRY_F, GRY_E, FG, 9.5)
remem = box(ax, 44, 12, 24, 6, "MUTUAL_REMEMBER\nkeep-stored + proof-ok", GRY_F, GRY_E, FG, 9.5)
away  = box(ax, 70, 12, 18, 6, "AWAY (brb)\nheld; clears", AMB_F, AMB_E, AMB_T, 9.5)
good  = box(ax, 41, 3.5, 22, 5, "✓ clean disconnect", GREEN_F, GREEN_E, GREEN_T, 10, "oval")

# divergences (right rail)
d1 = box(ax, 86, 82, 22, 6, "D1 connected,\nnever joined >12s", RED_F, RED_E, RED_T, 9)
d6 = box(ax, 86, 73, 22, 6, "D6 sync silent\nwhile live >90s", RED_F, RED_E, RED_T, 9)
d5 = box(ax, 86, 62, 22, 6, "D5 ceremony room\nsolo >10min", RED_F, RED_E, RED_T, 9)
d2 = box(ax, 86, 51, 22, 6, "D2 claimed pair,\nno completion >30s", RED_F, RED_E, RED_T, 9)
d4 = box(ax, 86, 41, 22, 6, "D4 'connecting' →\nneither ready/failed", RED_F, RED_E, RED_T, 9)
d3 = box(ax, 86, 9, 22, 6, "D3 peer gone,\nyou orphaned >15s", RED_F, RED_E, RED_T, 9)

arrow(ax, proc, conn)
arrow(ax, conn, join, "join")
arrow(ax, conn, d1, "≤12s", RED_E, RED_T, "--", rad=-0.1, lx=0.55)
arrow(ax, join, wait, "pair-create", lx=0.5)
arrow(ax, join, subs, "subscribe", lx=0.5)
arrow(ax, join, lstn, "listen", lx=0.5)
arrow(ax, join, d6, "gap", RED_E, RED_T, "--", rad=0.2, lx=0.6)
arrow(ax, wait, paired, "claim-ok", lx=0.5)
arrow(ax, wait, d5, "solo", RED_E, RED_T, "--", rad=-0.2, lx=0.6)
arrow(ax, subs, paired, "known-peer", lx=0.5)
arrow(ax, lstn, paired, "peer-joined", rad=0.15, lx=0.5)
arrow(ax, paired, tport)
arrow(ax, paired, d2, ">30s", RED_E, RED_T, "--", rad=-0.2, lx=0.55)
arrow(ax, tport, wrtc, "browser\ninvolved", lx=0.5)
arrow(ax, tport, dire, "cli↔cli\nreachable", GREEN_E, GREEN_T, lx=0.5)
arrow(ax, wrtc, ready, "ICE ok", lx=0.55)
arrow(ax, wrtc, d4, "silent", RED_E, RED_T, "--", rad=0.25, lx=0.82)
arrow(ax, dire, ready, "dialed", GREEN_E, GREEN_T, lx=0.55)
arrow(ax, dire, wrtc, "fail→fallback", AMB_E, AMB_T, "--", rad=0.3, lx=0.5)
arrow(ax, ready, xfer)
arrow(ax, ready, remem)
arrow(ax, ready, away)
arrow(ax, xfer, good, rad=0.1)
arrow(ax, remem, good)
arrow(ax, good, d3, "peer left", RED_E, RED_T, "--", rad=-0.15, lx=0.6)

# resilience legend (bottom-left)
ax.text(2, 30, "resilience overlays (legal, not divergence):\n"
        "• hidden/frozen → brb → peers hold the line\n"
        "• fresh sid → session.invalidate() → re-sync (C30)\n"
        "• lost emit → next sync tick repairs (gate L)\n"
        "• missed peer-join/left → roster digest (C30 p2)\n"
        "• one-sided transfer/trust → link state-ping (C30 p3)",
        ha="left", va="top", color=AMB_T, fontsize=8.5, family="DejaVu Sans")
fig.savefig("/root/.claude/jobs/330c2366/tmp/diagram-state-machine.png", dpi=160, facecolor=BG, bbox_inches="tight")
print("state machine done")
