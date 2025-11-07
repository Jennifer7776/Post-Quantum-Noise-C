#!/usr/bin/env bash
set -euo pipefail

SRV_NS=${1:-srv_ns}
CLI_NS=${2:-cli_ns}
SRV_IP=${SRV_IP:-10.0.0.1/24}
CLI_IP=${CLI_IP:-10.0.0.2/24}
VETH_SRV=${VETH_SRV:-veth_srv0}
VETH_CLI=${VETH_CLI:-veth_cli0}

echo "[INFO] Target namespaces: server=${SRV_NS} client=${CLI_NS}"
echo "[INFO] IPs: server=${SRV_IP} client=${CLI_IP}"
echo "[INFO] veth names: ${VETH_SRV} <-> ${VETH_CLI}"

# All operations requiring root privileges should be performed using sudo.
sudo mkdir -p /run/netns || true
# Some systems do not allow make-shared; ignore failures.
if mountpoint -q /run/netns; then
  sudo mount --make-shared /run/netns 2>/dev/null || true
fi

# Clean up old ones
if ip netns list | grep -q "^${SRV_NS}\b"; then sudo ip netns del "${SRV_NS}" || true; fi
if ip netns list | grep -q "^${CLI_NS}\b"; then sudo ip netns del "${CLI_NS}" || true; fi
if ip link show "${VETH_SRV}" &>/dev/null; then sudo ip link del "${VETH_SRV}" || true; fi
if ip link show "${VETH_CLI}" &>/dev/null; then sudo ip link del "${VETH_CLI}" || true; fi

# Create namespace
sudo ip netns add "${SRV_NS}"
sudo ip netns add "${CLI_NS}"

# Create veth
sudo ip link add "${VETH_SRV}" type veth peer name "${VETH_CLI}"

# Insert both ends of veth into their respective ns
sudo ip link set "${VETH_SRV}" netns "${SRV_NS}"
sudo ip link set "${VETH_CLI}" netns "${CLI_NS}"

# Configure address, enable interface and lo
sudo ip netns exec "${SRV_NS}" ip addr add "${SRV_IP}" dev "${VETH_SRV}"
sudo ip netns exec "${CLI_NS}" ip addr add "${CLI_IP}" dev "${VETH_CLI}"
sudo ip netns exec "${SRV_NS}" ip link set lo up
sudo ip netns exec "${CLI_NS}" ip link set lo up
sudo ip netns exec "${SRV_NS}" ip link set "${VETH_SRV}" up
sudo ip netns exec "${CLI_NS}" ip link set "${VETH_CLI}" up

# Optional: Default route (usually not needed if both ends are on the same network segment)

# sudo ip netns exec "${SRV_NS}" ip route add default dev "${VETH_SRV}" || true
# sudo ip netns exec "${CLI_NS}" ip route add default dev "${VETH_CLI}" || true

echo "[OK] namespaces ready."
echo "Test ping:"
sudo ip netns exec "${CLI_NS}" ping -c 1 -W 1 10.0.0.1 || true
