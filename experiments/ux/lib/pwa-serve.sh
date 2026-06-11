#!/usr/bin/env bash
# pwa-serve.sh — a tiny static HTTP server for the PWA-update e2e that can SWAP
# its /sw.js (simulating a real deploy of "build B"). The frontend's same-origin
# dist is served as build A; when the driver writes "GO" to the swap flag, the
# server serves build B's /sw.js (a fresh BUILD_ID) so the running SW discovers a
# waiting update — the genuine deploy-freshness path.
#
#   pwa-serve.sh <id> <workdir>        start  -> writes <workdir>/<id>-url.txt
#   pwa-serve.sh stop <id> <workdir>   stop
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"

if [ "${1:-}" = stop ]; then
  id="$2"; work="$3"
  pidf="$work/$id-pwa.pid"
  [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null
  rm -f "$pidf"
  exit 0
fi

id="$1"; work="$2"
DIST="$REPO_ROOT/frontend/dist"
[ -f "$DIST/index.html" ] || { echo "[pwa] no dist; build the frontend first" >&2; exit 1; }
[ -f "$DIST/sw.js" ] || { echo "[pwa] dist has no sw.js (PROD build with the SW plugin required)" >&2; exit 1; }

# free port
port=8310
while ( exec 3<>"/dev/tcp/127.0.0.1/$port" ) 2>/dev/null; do port=$((port+1)); done

# "build B" sw.js: same SW with a different BUILD_ID so its cache name differs and
# the running SW sees a byte-different /sw.js (a real update).
swapdir="$work/$id-buildB"; mkdir -p "$swapdir"
sed "s/filament-[A-Za-z0-9_.-]*/filament-buildB-$RANDOM/" "$DIST/sw.js" > "$swapdir/sw.js" 2>/dev/null || cp "$DIST/sw.js" "$swapdir/sw.js"
# ensure it really differs
echo "// build B $(date +%s%N)" >> "$swapdir/sw.js"

swap="$work/$id-swap.flag"; rm -f "$swap"

python3 - "$DIST" "$swapdir/sw.js" "$swap" "$port" <<'PY' &
import http.server, os, sys, socketserver
dist, swjs, swapflag, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k): super().__init__(*a, directory=dist, **k)
    def do_GET(self):
        # serve build B's sw.js once the swap flag is set
        if self.path.split('?')[0] in ('/sw.js',) and os.path.exists(swapflag):
            try:
                data = open(swjs, 'rb').read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers(); self.wfile.write(data); return
            except Exception: pass
        return super().do_GET()
    def end_headers(self):
        # never let the browser cache /sw.js or the shell so update() is honest
        if self.path.split('?')[0] in ('/sw.js', '/', '/index.html'):
            self.send_header('Cache-Control', 'no-cache')
        super().end_headers()
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('127.0.0.1', port), H) as s:
    s.serve_forever()
PY
echo $! > "$work/$id-pwa.pid"
echo "http://127.0.0.1:$port/" > "$work/$id-url.txt"

# wait for health
for i in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:$port/index.html" >/dev/null 2>&1 && exit 0
  sleep 0.2
done
echo "[pwa] server did not come up" >&2; exit 1
