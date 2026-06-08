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
def vstep(ax, a, b, label="", color=MUT, tc=MUT):
    """clean straight VERTICAL spine arrow (a above b)."""
    (x1,y1,w1,h1)=a; (x2,y2,w2,h2)=b
    ar = FancyArrowPatch((x1, y1-h1/2), (x2, y2+h2/2), arrowstyle="-|>",
                         mutation_scale=14, color=color, lw=1.7, zorder=1)
    ax.add_patch(ar)
    if label:
        ax.text((x1+x2)/2+3.2, (y1-h1/2+y2+h2/2)/2, label, ha="left", va="center",
                color=tc, fontsize=9, family="DejaVu Sans", zorder=4)

def stub(ax, a, b, label="", color=RED_E, tc=RED_T, left=False):
    """short HORIZONTAL dashed divergence stub between y-aligned boxes."""
    (x1,y1,w1,h1)=a; (x2,y2,w2,h2)=b
    sx = x1 - w1/2 if left else x1 + w1/2
    ex = x2 + w2/2 if left else x2 - w2/2
    ar = FancyArrowPatch((sx, y1), (ex, y2), arrowstyle="-|>", mutation_scale=12,
                         color=color, lw=1.4, ls="--", zorder=1)
    ax.add_patch(ar)
    if label:
        ax.text((sx+ex)/2, y1+1.6, label, ha="center", va="center", color=tc,
                fontsize=8, family="DejaVu Sans", zorder=4)

fig, ax = newfig(15, 13, "Filament — the session state machine (every state a client can be in)")
ax.text(50, 95.5, "vertical spine = the happy path   ·   red stubs = divergence (tel-watch.py)   ·   green = terminal-good",
        ha="center", color=MUT, fontsize=10)

SP = 42  # spine x
proc = box(ax, SP, 91, 15, 4, "process start", BLU_F, BLU_E, "white", 10, "oval")
conn = box(ax, SP, 83, 19, 5, "CONNECTING", GRY_F, GRY_E, FG, 11)
join = box(ax, SP, 73, 30, 6, "JOINED  (in a room)\n↺ sync heartbeat", GRY_F, GRY_E, FG, 11)

wait = box(ax, 15, 61, 22, 6.5, "WAITING_CLAIM\ncode shown", GRY_F, GRY_E, FG, 9.5)
subs = box(ax, SP, 61, 20, 6.5, "SUBSCRIBED\nchannels raised", GRY_F, GRY_E, FG, 9.5)
lstn = box(ax, 65, 61, 20, 6.5, "LISTENING\nrecv / up", GRY_F, GRY_E, FG, 9.5)

paired = box(ax, SP, 50, 30, 6, "PAIRED_ROOM   two sids, one room", GRY_F, BLU_E, BLU_T, 10)
tport  = box(ax, SP, 41, 22, 5.5, "◆  TRANSPORT?", BLU_F, BLU_E, BLU_T, 11)
wrtc   = box(ax, 26, 31, 24, 6.5, "WEBRTC / ICE\nSTUN + TURN, ≤25s", GRY_F, GRY_E, FG, 9.5)
dire   = box(ax, 58, 31, 24, 6.5, "DIRECT  TCP/QUIC\nNoise PSK, 1-RTT", GRY_F, GREEN_E, GREEN_T, 9.5)

ready = box(ax, SP, 21, 19, 5.5, "CONNECTED", GREEN_F, GREEN_E, GREEN_T, 11)
xfer  = box(ax, 15, 11, 24, 6.5, "TRANSFER\noffered → complete", GRY_F, GRY_E, FG, 9.5)
remem = box(ax, SP, 11, 25, 6.5, "MUTUAL_REMEMBER\nkeep + proof", GRY_F, GRY_E, FG, 9.5)
away  = box(ax, 67, 11, 17, 6.5, "AWAY (brb)\nheld; clears", AMB_F, AMB_E, AMB_T, 9.5)
good  = box(ax, SP, 2.5, 24, 4.5, "✓ clean disconnect", GREEN_F, GREEN_E, GREEN_T, 10, "oval")

# divergences — right rail, each ALIGNED to its source state's y (clean stubs)
RX = 87
d1 = box(ax, RX, 83, 20, 6, "D1  connected,\nnever joined", RED_F, RED_E, RED_T, 8.5)
d6 = box(ax, RX, 73, 20, 6, "D6  sync silent\nwhile live", RED_F, RED_E, RED_T, 8.5)
d5 = box(ax, RX, 61, 20, 6, "D5  ceremony room\nsolo >10min", RED_F, RED_E, RED_T, 8.5)
d2 = box(ax, RX, 50, 20, 6, "D2  claimed pair,\nno completion", RED_F, RED_E, RED_T, 8.5)
d4 = box(ax,  9, 31, 15, 7, "D4  'connecting'\nnever resolves", RED_F, RED_E, RED_T, 8.5)
d3 = box(ax, RX, 7,  20, 6, "D3  peer gone,\nyou orphaned", RED_F, RED_E, RED_T, 8.5)

# spine (straight vertical)
vstep(ax, proc, conn)
vstep(ax, conn, join, "join")
vstep(ax, join, subs)
vstep(ax, paired, tport)
vstep(ax, ready, remem)
# fan-out from JOINED to the three entry modes, and back into PAIRED_ROOM
for nd, lb in ((wait,"pair-create"), (lstn,"listen")):
    arrow(ax, join, nd, lb, lx=0.5)
for nd, lb in ((wait,"claim-ok"), (subs,"known-peer"), (lstn,"peer-joined")):
    arrow(ax, nd, paired, lb, lx=0.5)
# transport fork + rejoin
arrow(ax, tport, wrtc, "browser", lx=0.5)
arrow(ax, tport, dire, "cli↔cli", GREEN_E, GREEN_T, lx=0.5)
arrow(ax, wrtc, ready, "ICE ok", lx=0.55)
arrow(ax, dire, ready, "dialed", GREEN_E, GREEN_T, lx=0.55)
arrow(ax, dire, wrtc, "fail →\nfallback", AMB_E, AMB_T, "--", rad=0.3, lx=0.5)
# outcomes
arrow(ax, ready, xfer)
arrow(ax, ready, away)
arrow(ax, xfer, good, lx=0.5)
arrow(ax, remem, good)
arrow(ax, away, good, lx=0.5)
# divergence stubs (aligned, no diagonals)
stub(ax, conn, d1, ">12s")
stub(ax, join, d6, "gap>90s")
stub(ax, lstn, d5, ">10min")
stub(ax, paired, d2, ">30s")
stub(ax, wrtc, d4, ">25s", left=True)
stub(ax, good, d3, "peer left")

# resilience panel — its own bordered box in the clear lower-right quadrant
box(ax, 84, 30, 30, 26,
    "RESILIENCE OVERLAYS\n(legal — these self-correct,\nnever a divergence)\n\n"
    "hidden/frozen → brb,\n    peers hold the line\n"
    "fresh sid → invalidate\n    → re-sync  (C30)\n"
    "lost emit → next sync\n    tick repairs  (gate L)\n"
    "missed peer-join/left\n    → roster digest  (p2)\n"
    "1-sided transfer/trust\n    → link state-ping  (p3)",
    "#10171f", AMB_E, AMB_T, 8.5)
fig.savefig("/root/.claude/jobs/330c2366/tmp/diagram-state-machine.png", dpi=160, facecolor=BG, bbox_inches="tight")
print("state machine done")
