#!/bin/bash

# ===============================
#  IOAM 4-Node IPv6 Simulation
# ===============================

# === CONFIGURATION ===
TRACE_TYPE=0x600000
# looks like other field masks doesnt work
TRACE_SIZE=64
NAMESPACE_ID=123
SCHEMA_ID=777
SCHEMA_DATA="basic full trace schema"
USE_IOAM=true
NUM_ROUTERS=2             # Can be 1 or 2
STRESS_NETWORK=false
DUMP_PCAPS=false
RUN_TRACEPATH=true
KEEP_ALIVE=true
DEBUG=true

# === Binary Path for Custom IOAM ip ===
IP_BIN="/home/omer/iproute2/ip/ip"
TRACE_BIN="/home/omer/iputils/build/tracepath"

# === Nodes and Links ===
NODES=(host_a router1 router2 host_b)
LINKS=(a-r1 r1-r2 r2-b)

# === IP Addresses ===
IP_A="fd00::a/64"
IP_R1A="fd00::1/64"
IP_R1B="fd02::1/64"
IP_B="fd02::b/64"

# Optional second router
IP_R2A="fd02::2/64"
IP_R2B="fd03::1/64"
IP_B_2="fd03::b/64"

# === Cleanup Existing Setup ===
cleanup() {
  ip netns del host_a 2>/dev/null || true
  ip netns del router1 2>/dev/null || true
  ip netns del host_b 2>/dev/null || true
  [ "$NUM_ROUTERS" -eq 2 ] && ip netns del router2 2>/dev/null || true
  ip link del veth-a-r1 2>/dev/null || true
  ip link del veth-r1-r2 2>/dev/null || true
  ip link del veth-r2-b 2>/dev/null || true
  ip link del veth-r1-b 2>/dev/null || true
  ip link del veth-b-r1 2>/dev/null || true
}

# === Debug Print ===
log() {
  [ "$DEBUG" = true ] && echo -e "$@"
}

# === Setup Topology ===
setup_topology() {
  log "[*] Setting up namespaces and veth links"

  ip netns add host_a
  ip netns add router1
  ip netns add host_b

  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip netns add router2
  fi

  ip link add veth-a-r1 type veth peer name veth-r1-a
  ip link set veth-a-r1 netns host_a
  ip link set veth-r1-a netns router1

  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip link add veth-r1-r2 type veth peer name veth-r2-r1
    ip link set veth-r1-r2 netns router1
    ip link set veth-r2-r1 netns router2
    ip link add veth-r2-b type veth peer name veth-b-r2
    ip link set veth-r2-b netns router2
    ip link set veth-b-r2 netns host_b
  else
    ip link add veth-r1-b type veth peer name veth-b-r1
    ip link set veth-r1-b netns router1
    ip link set veth-b-r1 netns host_b
  fi

  ip netns exec host_a ip link set veth-a-r1 name veth0
  ip netns exec router1 ip link set veth-r1-a name veth0
  ip netns exec host_b ip link set veth-b-r2 name veth0 2>/dev/null || ip netns exec host_b ip link set veth-b-r1 name veth0

  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip netns exec router1 ip link set veth-r1-r2 name veth1
    ip netns exec router2 ip link set veth-r2-r1 name veth0
    ip netns exec router2 ip link set veth-r2-b name veth1
  else
    ip netns exec router1 ip link set veth-r1-b name veth1
  fi

  ip netns exec host_a ip -6 addr add $IP_A dev veth0
  ip netns exec router1 ip -6 addr add $IP_R1A dev veth0

  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip netns exec router1 ip -6 addr add $IP_R1B dev veth1
    ip netns exec router2 ip -6 addr add $IP_R2A dev veth0
    ip netns exec router2 ip -6 addr add $IP_R2B dev veth1
    ip netns exec host_b ip -6 addr add $IP_B_2 dev veth0
  else
    ip netns exec router1 ip -6 addr add $IP_R1B dev veth1
    ip netns exec host_b ip -6 addr add $IP_B dev veth0
  fi

  for ns in host_a router1 host_b; do
    ip netns exec $ns ip link set lo up 2>/dev/null || true
    ip netns exec $ns ip link set veth0 up 2>/dev/null || true
    ip netns exec $ns ip link set veth1 up 2>/dev/null || true
  done

  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip netns exec router2 ip link set lo up 2>/dev/null || true
    ip netns exec router2 ip link set veth0 up 2>/dev/null || true
    ip netns exec router2 ip link set veth1 up 2>/dev/null || true
  fi

  ip netns exec router1 sysctl -qw net.ipv6.conf.all.forwarding=1
  [ "$NUM_ROUTERS" -eq 2 ] && [ "$NUM_ROUTERS" -eq 2 ] && ip netns exec router2 sysctl -qw net.ipv6.conf.all.forwarding=1

  ip netns exec host_a ip -6 route add fd02::/64 via fd00::1 dev veth0
  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip netns exec host_a ip -6 route add fd03::/64 via fd00::1 dev veth0
    ip netns exec router1 ip -6 route add fd03::/64 via fd02::2 dev veth1
    ip netns exec router2 ip -6 route add fd00::/64 via fd02::1 dev veth0
    ip netns exec host_b ip -6 route add fd00::/64 via fd03::1 dev veth0
  else
    ip netns exec host_b ip -6 route add fd00::/64 via fd02::1 dev veth0
  fi
}

# === IOAM Configuration ===
configure_ioam() {
  if [ "$USE_IOAM" != true ]; then
    log "[*] Skipping IOAM setup (regular IPv6 mode)"
    return
  fi

  log "[*] Configuring IOAM"

  ip netns exec host_a sysctl -w net.ipv6.conf.veth0.ioam6_id=1
  ip netns exec host_a sysctl -w net.ipv6.conf.veth0.ioam6_enabled=1

  ip netns exec router1 sysctl -w net.ipv6.conf.veth0.ioam6_enabled=1
  ip netns exec router1 sysctl -w net.ipv6.conf.veth1.ioam6_enabled=1
  ip netns exec router1 sysctl -w net.ipv6.ioam6_id=11

  if [ "$NUM_ROUTERS" -eq 2 ]; then
    ip netns exec router2 sysctl -w net.ipv6.conf.veth0.ioam6_enabled=1
    ip netns exec router2 sysctl -w net.ipv6.conf.veth1.ioam6_enabled=1
    ip netns exec router2 sysctl -w net.ipv6.ioam6_id=22
  fi

  ip netns exec host_a $IP_BIN ioam namespace add $NAMESPACE_ID
  ip netns exec host_a $IP_BIN ioam schema add $SCHEMA_ID "$SCHEMA_DATA"
  ip netns exec host_a $IP_BIN ioam namespace set $NAMESPACE_ID schema $SCHEMA_ID

  if [ "$NUM_ROUTERS" -eq 2 ]; then
  ip netns exec host_a ip -6 route replace fd03::/64 via fd00::1 encap ioam6 \
   mode inline trace prealloc type $TRACE_TYPE ns $NAMESPACE_ID size $TRACE_SIZE dev veth0
  else
  ip netns exec host_a ip -6 route replace fd02::/64 via fd00::1 encap ioam6 \
   mode inline trace prealloc type $TRACE_TYPE ns $NAMESPACE_ID size $TRACE_SIZE dev veth0
  fi
}


# === Stress Simulation ===
apply_stress() {
  if [ "$STRESS_NETWORK" = true ]; then
    log "[*] Applying network stress via tc"
    ip netns exec router1 tc qdisc add dev veth0 root netem delay 50ms loss 1%
    ip netns exec router2 tc qdisc add dev veth0 root netem delay 100ms loss 3%
  fi
}

# === Traffic + Capture ===
run_traffic() {
  if [ "$DUMP_PCAPS" = true ]; then
    for ns in host_a router1 router2 host_b; do
      ip netns exec $ns tcpdump -i any ip6 -w /home/omer/${ns}.pcap &
    done
  fi

  sleep 1

  if [ "$RUN_TRACEPATH" = true ]; then
    log "[*] Running custom tracepath6 from host_a to host_b"
    if [ "$NUM_ROUTERS" -eq 2 ]; then
      ip netns exec host_a $TRACE_BIN -n -6 -m 5 fd03::b
    else
      ip netns exec host_a $TRACE_BIN -n -6 -m 5 fd02::b
    fi
  else
    log "[*] Running ping6 from host_a to host_b"
    if [ "$NUM_ROUTERS" -eq 2 ]; then
      ip netns exec host_a ping -6 -c 5 fd03::b
    else
      ip netns exec host_a ping -6 -c 5 fd02::b
    fi
  fi

  sleep 2
  pkill tcpdump 2>/dev/null || true
}

# === MAIN ===
cleanup
setup_topology
configure_ioam
apply_stress
run_traffic

if [ "$KEEP_ALIVE" != true ]; then
  log "[*] Cleaning up..."
  cleanup
else
  log "[+] Simulation complete. Namespaces left running for inspection."
fi
