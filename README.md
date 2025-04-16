# IOAM IPv6 Simulation Demo

This project simulates an IPv6 topology using Linux network namespaces with In-Situ Operations, Administration, and Maintenance (IOAM) support. It includes a patched version of `tracepath` that can parse IOAM trace data from Hop-by-Hop extension headers.

---

## 📁 Project Structure

- `ioam_ipv6_4node_demo_v2.sh` – Bash script that creates a simulated network with 1 or 2 routers, configures IOAM, and runs a custom tracepath.
- `tracepath.c` – Modified version of the original `tracepath` tool with IOAM decoding logic.

---

## 🚀 Script Overview

`ioam_ipv6_4node_demo_v2.sh` sets up a 4-node IPv6 topology:

- **host_a** → **router1** → [optional **router2**] → **host_b**
- All nodes are created using `ip netns` and interconnected with `veth` pairs.

### 🔧 Script Options (configured via variables):

- `NUM_ROUTERS` – Set to `1` or `2` to choose topology complexity.
- `USE_IOAM` – Toggle IOAM on/off.
- `TRACE_TYPE` – IOAM trace fields (e.g., `0x600000` = Node ID + Timestamp).
- `TRACE_SIZE` – Preallocated IOAM trace size in bytes.
- `DUMP_PCAPS` – Enables packet capture per namespace.
- `RUN_TRACEPATH` – Whether to run the custom tracepath or fallback to ping.
- `KEEP_ALIVE` – Leave namespaces up for manual inspection.

---

## 🛠️ Major Modifications to tracepath.c

We extended the classic `tracepath` utility (from iputils) with support for parsing IPv6 Hop-by-Hop headers containing IOAM trace data (per RFC 9197):

### ✅ IOAM Enhancements:

- Enabled socket options:
  - `IPV6_RECVHOPOPTS`
  - `IPV6_HOPLIMIT`
- Hooked into `recvmsg()`’s control message buffer to detect and extract IOAM trace options (option type `0x0E`).
- Decoded fields based on `TRACE_TYPE` (bitmask):
  - Node ID (32-bit)
  - Ingress IF (32-bit)
  - Egress IF (32-bit)
  - Timestamp (32-bit)
  - AppData or Latency, HopCount, QueueDepth depending on configuration
- Calculated average IOAM RTT across all hops
- Formatted pretty output like:
  ```
  IOAM Node ID: 11
  Ingress IF: 2, Egress IF: 3
  Timestamp: 12345678
  App Data: 9999
  ```

---

## 🧪 Example Output

```
[*] Running custom tracepath6 from host_a to host_b
Receiving errors for TTL 1...
>>> Checking for IOAM Hop-by-Hop headers
>>> Found IOAM trace option (0x0E), 2 entries
  IOAM Node ID: 11, Timestamp: 1683721
  IOAM Node ID: 22, Timestamp: 1683822
 1:  ???  0.225ms [IOAM avg RTT: 0.612 ms]
```

---

## 🧱 Challenges Faced

### 1. ❌ IOAM Route Not Working
- Even with `ip route ... encap ioam6`, default `iproute2` didn’t support IOAM.
- Fixed by compiling `iproute2` from an **IOAM-enabled fork** (Intel’s or patched).

### 2. ❌ IOAM Trace Option Missing
- IOAM wasn’t inserted unless:
  - All routers had `sysctl ioam6_enabled=1` per interface.
  - The route used the correct `encap ioam6 ...` configuration.

### 3. ⚠️ Control Messages Not Parsing
- Initial `tracepath` didn’t request `IPV6_RECVHOPOPTS`.
- Fix: set necessary `setsockopt()` flags + decode options via `CMSG_DATA()`

### 4. 📉 Output Parsing Bugs
- Option lengths varied by trace type
- Added bounds-checking and fallback logic to handle incomplete or malformed options

---

## 📦 Dependencies

- Linux with IOAM-enabled kernel (6.1+ or patched)
- `iproute2` fork with IOAM support
- Rebuilt `tracepath` (from iputils) with `tracepath.c` replaced

---
