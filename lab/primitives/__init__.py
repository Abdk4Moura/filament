"""primitives/ — the 7 composable building blocks of the lab.

Each is a small module with a documented, single-responsibility interface. The
providers (the LINK primitive) compose the others. The seven:

  1. tun    (tun.py)    — create a TUN iface in a node's netns, assign IP/subnet.
  2. link   (../providers/) — the pluggable carrier between two endpoints.
  3. frame  (frame.py)  — IP packet <-> link frame (length-prefix); shared by the
                          udp and filament carriers.
  4. route  (route.py)  — the allowed-IPs / dest-IP -> peer table (the WG model).
  5. crypto (crypto.py) — none | wg-noise | dtls (a declarative selector; the
                          carrier supplies the actual encryption).
  6. fault  (fault.py)  — induce loss/latency/bandwidth (tc netem) and STALL
                          (freeze the data path while the link stays "up").
  7. probe  (../probe/) — drive + measure across the tunnel (ping/iperf3/curl,
                          counters) with machine-readable output.
"""
