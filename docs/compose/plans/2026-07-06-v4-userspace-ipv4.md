# V4: Userspace-netstack IPv4 Implementation Plan

> Status: historical plan (2026-07-06). Retained as implementation context; verify against the tree before resuming any unchecked work.

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add IPv4 support to the userspace netstack for zero-privilege containers

**Architecture:** Extend the existing smoltcp interface to handle both IPv4 and IPv6 in a single stack, maintaining backward compatibility with IPv6-only usage.

**Tech Stack:** Rust, smoltcp, tokio

---

## File Structure

**Modified:**
- `cli/src/tun/netstack.rs` - Core netstack: add IPv4 support to `NetstackTun::open()`, `poll_loop()`, `dial()`, `listen()`
- `cli/src/tun/mod.rs` - Update `TunDevice` trait if needed for dual-stack
- `cli/src/l3.rs` - Update `L3::start()` to pass IPv4 CIDR to netstack

**Tests:**
- `cli/src/tun/netstack.rs` - Extend existing tests + add IPv4-specific tests

---

### Task 1: Add IPv4 CIDR parsing

**Covers:** [S3]

**Files:**
- Modify: `cli/src/tun/netstack.rs:628-640`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parses_ipv4_cidr() {
    let (addr, prefix) = parse_v4_cidr("192.168.1.1/24").unwrap();
    assert_eq!(addr, std::net::Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(prefix, 24);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release parses_ipv4_cidr`
Expected: FAIL with "function not defined"

- [ ] **Step 3: Write minimal implementation**

```rust
fn parse_v4_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (a, p) = match cidr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().map_err(|_| anyhow!("bad prefix in '{cidr}'"))?),
        None => (cidr, 32),
    };
    let addr: std::net::Ipv4Addr = a
        .parse()
        .map_err(|_| anyhow!("netstack overlay address must be IPv4, got '{a}'"))?;
    if p > 32 {
        bail!("prefix /{p} out of range for IPv4");
    }
    Ok((addr, p))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release parses_ipv4_cidr`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli/src/tun/netstack.rs
git commit -m "netstack: add IPv4 CIDR parsing"
```

---

### Task 2: Update NetstackTun::open() for dual-stack

**Covers:** [S2, S3]

**Files:**
- Modify: `cli/src/tun/netstack.rs:264-310`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn netstack_opens_with_ipv4() {
    let v4_addr = std::net::Ipv4Addr::new(192, 168, 1, 1);
    let v6_addr: Ipv6Addr = "fdf1:1af7:c30d::1".parse().unwrap();
    let tun = NetstackTun::open_dual("filament0", &v6_addr, 128, Some((v4_addr, 24)), 1280);
    assert!(tun.is_ok());
    let tun = tun.unwrap();
    assert_eq!(tun.addr(), v6_addr);
    assert_eq!(tun.addr_v4(), Some(v4_addr));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release netstack_opens_with_ipv4`
Expected: FAIL with "function not defined"

- [ ] **Step 3: Write minimal implementation**

Add `addr_v4` field to `NetstackTun` and `open_dual()` method:

```rust
pub struct NetstackTun {
    name: String,
    addr: Ipv6Addr,
    addr_v4: Option<std::net::Ipv4Addr>,
    // ... existing fields
}

impl NetstackTun {
    /// Open with dual-stack support (IPv6 mandatory, IPv4 optional).
    pub fn open_dual(
        name: &str,
        v6_addr: &Ipv6Addr,
        v6_prefix: u8,
        v4_cidr: Option<(std::net::Ipv4Addr, u8)>,
        mtu: u32,
    ) -> Result<NetstackTun> {
        // ... implementation
    }

    /// This node's v4 overlay address (if configured).
    pub fn addr_v4(&self) -> Option<std::net::Ipv4Addr> {
        self.addr_v4
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release netstack_opens_with_ipv4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli/src/tun/netstack.rs
git commit -m "netstack: add dual-stack open with IPv4 support"
```

---

### Task 3: Update poll_loop for IPv4 routing

**Covers:** [S2, S4]

**Files:**
- Modify: `cli/src/tun/netstack.rs:374-589`

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn netstack_ipv4_route_works() {
    let a_addr: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
    let a_v6: Ipv6Addr = "fdf1:1af7:c30d::1".parse().unwrap();
    let b_addr: std::net::Ipv4Addr = "192.168.1.2".parse().unwrap();
    let b_v6: Ipv6Addr = "fdf1:1af7:c30d::2".parse().unwrap();
    let a = Arc::new(NetstackTun::open_dual("filament0", &a_v6, 128, Some((a_addr, 24)), 1280).unwrap());
    let b = Arc::new(NetstackTun::open_dual("filament0", &b_v6, 128, Some((b_addr, 24)), 1280).unwrap());
    // ... cross-wire and test IPv4 connectivity
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release netstack_ipv4_route_works`
Expected: FAIL with route not working

- [ ] **Step 3: Write minimal implementation**

Update `poll_loop` to handle IPv4 packets:
- Add IPv4 default route in `open_dual()`
- Handle IPv4 packets in the poll loop
- Route IPv4 packets to appropriate destination

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release netstack_ipv4_route_works`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli/src/tun/netstack.rs
git commit -m "netstack: add IPv4 routing in poll loop"
```

---

### Task 4: Update dial/listen for IPv4

**Covers:** [S2, S4]

**Files:**
- Modify: `cli/src/tun/netstack.rs:322-341`

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn netstack_ipv4_dial_listen() {
    let a_addr: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
    let b_addr: std::net::Ipv4Addr = "192.168.1.2".parse().unwrap();
    // ... setup two netstacks and test IPv4 dial/listen
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release netstack_ipv4_dial_listen`
Expected: FAIL with dial/listen not working for IPv4

- [ ] **Step 3: Write minimal implementation**

Update `dial()` and `listen()` to accept `IpAddress` (both v4 and v6):

```rust
pub async fn dial_addr(&self, dst: IpAddress, port: u16) -> Result<NetstackStream> {
    // ... handle both IPv4 and IPv6
}

pub async fn listen_addr(&self, port: u16) -> Result<NetstackListener> {
    // ... listen on both families
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release netstack_ipv4_dial_listen`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli/src/tun/netstack.rs
git commit -m "netstack: add IPv4 dial/listen support"
```

---

### Task 5: Update L3 to pass IPv4 CIDR

**Covers:** [S2, S3]

**Files:**
- Modify: `cli/src/l3.rs:170-175`

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn l3_start_with_ipv4() {
    // ... test that L3::start passes IPv4 CIDR to netstack
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release l3_start_with_ipv4`
Expected: FAIL with IPv4 not configured

- [ ] **Step 3: Write minimal implementation**

Update `L3::start()` to pass IPv4 CIDR when available:

```rust
let open_netstack = || -> Result<(Arc<dyn TunDevice>, Option<Arc<NetstackTun>>)> {
    let v4_cidr = identity.as_ref().map(|id| (id.addr_v4(), 24));
    let ns = Arc::new(NetstackTun::open_dual(IFNAME, &addr, 128, v4_cidr, mtu)?);
    Ok((ns.clone() as Arc<dyn TunDevice>, Some(ns)))
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release l3_start_with_ipv4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli/src/l3.rs
git commit -m "l3: pass IPv4 CIDR to userspace netstack"
```

---

### Task 6: Add IPv4-specific tests

**Covers:** [S5]

**Files:**
- Modify: `cli/src/tun/netstack.rs`

- [ ] **Step 1: Write IPv4 connectivity test**

```rust
#[tokio::test]
async fn netstack_ipv4_connectivity() {
    // Test IPv4 packet routing between two netstacks
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test --release netstack_ipv4_connectivity`
Expected: PASS

- [ ] **Step 3: Write IPv4 lossy overlay test**

```rust
#[tokio::test]
async fn netstack_ipv4_lossy_overlay() {
    // Test IPv4 under packet loss
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release netstack_ipv4_lossy_overlay`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cli/src/tun/netstack.rs
git commit -m "netstack: add IPv4-specific tests"
```

---

### Task 7: Run full test suite and verify

**Covers:** [S5]

**Files:**
- None (verification only)

- [ ] **Step 1: Run all tests**

Run: `cargo test --release`
Expected: All tests pass

- [ ] **Step 2: Run live verification**

Deploy to dovm + other-do and verify IPv4 overlay connectivity.

- [ ] **Step 3: Final commit if needed**

```bash
git commit -m "V4: userspace-netstack IPv4 complete"
```
