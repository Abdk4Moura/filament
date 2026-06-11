# Safety & teardown runbook

The lab is built to be **careful**: everything is sandboxed in network
namespaces, teardown is leak-free even after a crash, and the host / live
filament are never touched. This runbook is the operational contract.

## Hard invariants (never violated)

1. **No host-network mutation.** Every iface/address/route/qdisc lives inside a
   `lab-`-prefixed netns, applied via `ip netns exec`. The only host-namespace
   operations are `ip netns add/del` and creating a veth pair that is
   *immediately* moved into the lab namespaces.
2. **Never touch the live system.** Not the running `filament up` daemon, not
   `~/.local/bin/filament`, not `~/.config/filament`, not the live site/T4. The
   `filament` link uses the **locally-built** `cli/target/release/filament` and
   **isolated** `FILAMENT_CONFIG_DIR` identities under `.state/logs/<lab>/`.
3. **Root only where needed.** netns/tun/wg require root; `lab doctor` and every
   `up` check it and fail clearly otherwise.

## The resource ledger (why teardown is safe)

Every host resource the lab creates is appended to `.state/<lab>.json` **as it is
created** — netns, veth, tun, wg iface, spawned PID, tc qdisc, scratch file.
`lab down` walks the ledger in **reverse** and destroys each. Because deleting a
netns frees any iface still inside it, netns deletion is the **backstop**: even
if an inner delete fails, removing the namespace reclaims it.

- **Idempotent `up`:** re-running reuses existing resources (no duplicates).
- **Partial/failed `up`:** the ledger is written incrementally and left in place
  on failure, so `lab down` still cleans up what was half-created.
- **`lab down --all`:** tears down every lab with a ledger, then sweeps any stray
  `lab-`-prefixed namespace AND any stray `lab*` iface left in the host ns (only
  possible from a crashed veth-add before relocation). The belt-and-suspenders
  cleanup.

## Routine cleanup

```bash
sudo lab/lab status                 # what's up, which processes are alive
sudo lab/lab down <lab>             # tear down one lab
sudo lab/lab down --all --purge-logs   # tear down everything + sweep + drop logs
```

## Verify no leaks (what the e2e asserts)

```bash
ls /var/run/netns | grep '^lab-'          # expect: nothing
ip -br link | grep -E 'labtun|labu-|labwg'  # expect: nothing in host ns
ps aux | grep -E 'relay\.py' | grep -v grep # expect: no relay processes
ls lab/.state/*.json                       # expect: no ledgers for torn-down labs
```

## If something is stuck

- **A lab won't fully tear down:** run `sudo lab/lab down <lab>` again (idempotent),
  then `sudo lab/lab down --all` to sweep strays.
- **Manual last resort** (only `lab-`-prefixed resources — never touch others):
  ```bash
  for ns in $(ls /var/run/netns | grep '^lab-'); do sudo ip netns del "$ns"; done
  for i in $(ip -br link | awk '{print $1}' | grep -E '^lab(tun|u-|wg)'); do sudo ip link del "$i"; done
  pkill -f 'fil_relay.py'; pkill -f 'udp_relay.py'
  # isolated filament endpoints (lab only — NEVER the real daemon):
  pkill -f 'FILAMENT_CONFIG_DIR=.*\.state/logs'
  rm -f lab/.state/*.json
  ```
- **Confirm the real daemon is untouched:** `filament status` should still show
  the live `up` daemon (its pid in `~/.config/filament/up.pid`). The lab's
  isolated endpoints never write there.

## Faults are namespaced too

`lab fault` applies `tc netem` to a carrier's data-path iface **inside a netns**
and records it in the ledger; `lab fault clear` (or any `lab down`) removes it.
A forgotten `stall` is cleared by teardown — it can never outlive the lab or
affect the host.
