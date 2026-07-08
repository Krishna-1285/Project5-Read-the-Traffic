#!/usr/bin/env bash
# gpu_fabric_check.sh — read the watch on the GPU cluster's wire.
# Verifies the prerequisites that distributed inference/training need on the
# east-west fabric: NVLink topology, RDMA-capable NICs, GPUDirect peer memory,
# and memlock limits. Read-only. Run on a GPU node before you blame the model.
set -euo pipefail

echo "== NVLink / intra-node fabric =="
# Headline number to watch for: ~1.8 TB/s/GPU on 5th-gen NVLink (as of 2026).
nvidia-smi nvlink --status 2>/dev/null | grep -E "Link|GB/s" || echo "  (no NVLink: PCIe-only node)"
echo
nvidia-smi topo -m 2>/dev/null || echo "  nvidia-smi topo unavailable"

echo; echo "== GPUDirect RDMA peer-memory module =="
if lsmod | grep -q nvidia_peermem; then
  echo "  OK: nvidia_peermem loaded (NIC can DMA into GPU memory)"
else
  echo "  MISSING: nvidia_peermem — RDMA will fall back to a CPU bounce buffer"
fi

echo; echo "== RDMA devices (InfiniBand / RoCEv2) =="
if command -v ibv_devinfo >/dev/null 2>&1; then
  ibv_devinfo 2>/dev/null | grep -E "hca_id|state|link_layer" || echo "  no active HCA"
else
  echo "  ibv_devinfo not installed (rdma-core)"
fi

echo; echo "== memlock ulimit (RDMA pins memory; must be unlimited) =="
mlock=$(ulimit -l)
[ "$mlock" = "unlimited" ] && echo "  OK: memlock unlimited" \
  || echo "  WARN: memlock=$mlock KB — RDMA registration may fail under load"

echo; echo "Done. A green check here means the interconnect won't be your bottleneck."
echo "It does NOT mean the cluster is healthy. Confirm with a real all-reduce. — Coach"
