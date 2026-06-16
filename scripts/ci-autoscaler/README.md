# ADO CI-agent autoscaler (project-ci-pool)

Demand-driven autoscaler that maintains a pool of **Incus container** Azure DevOps
build agents on the fleet node where the agents live (**dc12**). Containers, not VMs:
~1-2 s launch, live cgroup CPU/RAM resize, nested Docker via `security.nesting=true`
(validated — the nightly Docker lane runs inside them).

This is **dc12-only** operational tooling: the autoscaler runs solely on the node that
hosts the agents, so — unlike the hetzman VM templates — it is *not* shipped to the
rest of the fleet by `scripts/install.sh`. It lives here under version control because
its scripts run **as root on dc12** (root-RCE surface → must be auditable and pinned).

## Components

| File | Role |
|------|------|
| `bake-ci-agent-image.sh` | Builds the lean `ado-ci-agent` Incus image (apt toolchain, gh/az/yq, docker-ce with nesting, Python tool-cache, unpacked ADO agent 4.274.1 — *unregistered*). By default it bootstraps its tool-cache + agent seed from a throwaway container of the *current* image, so each re-bake chains from the prior image with **no VM/agent dependency** (override `SRC_AGENT=<container>` to seed from a specific source, as the very first image did from a VM agent). Deliberately omits the CONSTANCE BEAM/OTP build (unused by CI, ~20 min). |
| `ci-autoscaler.py` | The controller. Polls `pools/{id}/jobrequests`, scales `ci-agent-N` containers between `BASELINE` and `MAX_TOTAL`, reaps idle agents above baseline after a grace, and self-heals failed registrations (a container that never becomes an online pool agent within `REGISTER_GRACE_SECS` is reaped and relaunched). `flock` single-flight. |
| `ci-autoscaler.service` | systemd oneshot wrapper around the controller. |
| `ci-autoscaler.timer` | Fires the service every 30 s. |

## Design (owner-approved 2026-06-16, cap = 16 vCPU)

- **Baseline 2** persistent container agents @ 4 vCPU / 8 GB (8 vCPU at rest).
- **Burst to 4** total (16 vCPU peak) when the pool queue is deep, leaving headroom for
  the other VMs on the shared host.
- Managed-persistent model (scale the *count* of persistent agents by queue depth; reap
  idle above baseline) — simpler than per-job `--once` churn. `pytest-ci` is 8 independent
  jobs, so 2→4 agents halves wall-clock.

## Tunables (env, read by the service via `/root/ci-autoscaler/env`)

| Var | Default | Meaning |
|-----|---------|---------|
| `BASELINE` | `2` | persistent agents kept even at zero demand |
| `MAX_TOTAL` | `4` | hard ceiling (× `AGENT_CPU` = vCPU cap) |
| `AGENT_CPU` / `AGENT_MEM` | `4` / `8GiB` | per-agent limits (live-resizable) |
| `IDLE_GRACE_SECS` | `300` | how long an above-baseline agent must be idle before reaping |
| `REGISTER_GRACE_SECS` | `240` | how long a container may take to become an online agent before it is treated as a failed registration and reaped |

## Deploy / re-deploy on dc12

```bash
# 1. image (re-run whenever the toolset changes)
sudo bash bake-ci-agent-image.sh                 # publishes the `ado-ci-agent` alias

# 2. controller + units
sudo install -d -m 0700 /root/ci-autoscaler
sudo install -m 0755 ci-autoscaler.py /root/ci-autoscaler/
sudo install -m 0644 ci-autoscaler.service ci-autoscaler.timer /etc/systemd/system/
printf '%s' "<ADO-PAT>" | sudo tee /root/ci-autoscaler/pat >/dev/null   # 0600, never committed
sudo chmod 0600 /root/ci-autoscaler/pat
sudo systemctl daemon-reload
sudo systemctl enable --now ci-autoscaler.timer
```

The PAT file (`/root/ci-autoscaler/pat`) is a secret and is **never** committed — it is
written out-of-band at deploy time.

## Operate

```bash
sudo systemctl start ci-autoscaler.service            # force a tick now
sudo python3 /root/ci-autoscaler/ci-autoscaler.py     # dry-foreground (logs demand/online/desired)
journalctl -u ci-autoscaler.service -n 50 --no-pager  # recent ticks
incus list ci-agent-.* -c ns                          # live agents
```

## Provenance

The blocking defect — the ADO agent SIGABRT inside the container during `config.sh` —
was an EACCES on `_diag/Agent_*.log` (root-owned `_diag` left by a debug run as root,
then re-run as `ubuntu`). A *fresh* container never hits it. Root-caused via a four-agent
fan-out (strace evidence overruled the seccomp/io_uring red herring). The second defect
— an empty, root-owned baked Python tool-cache — is fixed in `bake-ci-agent-image.sh`
step `[4/6]` by copying the known-good `/opt/hostedtoolcache` from a working agent.
