#!/usr/bin/env python3
"""ci-autoscaler — demand-driven Incus-container agents for an Azure DevOps pool.

Model (managed-persistent, not per-job churn):
  * BASELINE persistent container agents are always kept online.
  * When the pool's queued+running job count exceeds the number of online
    agents, scale UP by launching more container agents — hard-capped at
    MAX_TOTAL (the shared-host vCPU budget: MAX_TOTAL * AGENT_CPU vCPU).
  * When there is no demand and online > BASELINE for longer than
    IDLE_GRACE_SECS, scale DOWN by deregistering + deleting the excess.

Each agent is an Incus *container* cloned from the pre-baked `ado-ci-agent`
image: ~1-2s launch, live cgroup resize, nested Docker. Containers register to
the pool as a systemd service inside the container, then self-host the agent.

Run as root on the fleet node, every ~30s via a systemd timer. Single-flight
via an flock. Reads the PAT from CONF_DIR/pat (mode 600). Idempotent + capped:
a crash leaves at most MAX_TOTAL containers; the next tick reconciles.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import subprocess
import sys
import time
import urllib.request

ORG = os.environ.get("ADO_ORG", "project-troy")
POOL_NAME = os.environ.get("POOL_NAME", "project-ci-pool")
IMAGE = os.environ.get("AGENT_IMAGE", "ado-ci-agent")
BASELINE = int(os.environ.get("BASELINE", "2"))
MAX_TOTAL = int(os.environ.get("MAX_TOTAL", "4"))          # 4 * 4 vCPU = 16 vCPU cap
AGENT_CPU = os.environ.get("AGENT_CPU", "4")
AGENT_MEM = os.environ.get("AGENT_MEM", "8GiB")
IDLE_GRACE_SECS = int(os.environ.get("IDLE_GRACE_SECS", "300"))
# A launched container that never becomes an online pool agent within this grace is
# treated as a failed registration and reaped so the next tick relaunches it fresh.
REGISTER_GRACE_SECS = int(os.environ.get("REGISTER_GRACE_SECS", "240"))
PREFIX = "ci-agent-"
CONF_DIR = os.environ.get("CONF_DIR", "/root/ci-autoscaler")
STATE_FILE = os.path.join(CONF_DIR, "idle-since.json")


def _pat() -> str:
    with open(os.path.join(CONF_DIR, "pat"), encoding="utf-8") as fh:
        return fh.read().strip()


def _auth_header() -> dict[str, str]:
    tok = base64.b64encode(f":{_pat()}".encode()).decode()
    return {"Authorization": "Basic " + tok}


def _api(path: str) -> dict:
    url = f"https://dev.azure.com/{ORG}/_apis/distributedtask/{path}"
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}api-version=7.1"
    req = urllib.request.Request(url, headers=_auth_header())
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def _api_delete(path: str) -> None:
    url = f"https://dev.azure.com/{ORG}/_apis/distributedtask/{path}?api-version=7.1"
    req = urllib.request.Request(url, method="DELETE", headers=_auth_header())
    try:
        urllib.request.urlopen(req, timeout=30).read()
    except urllib.error.HTTPError as exc:  # 404 = already gone — fine
        if exc.code not in (404, 204):
            raise


def _incus(*args: str, check: bool = True, capture: bool = True) -> str:
    res = subprocess.run(
        ["incus", *args], capture_output=capture, text=True, check=check, timeout=120
    )
    return (res.stdout or "").strip()


def pool_id() -> int:
    pools = _api(f"pools?poolName={POOL_NAME}")
    return pools["value"][0]["id"]


def demand(pid: int) -> int:
    """queued + running job count for this pool."""
    reqs = _api(f"pools/{pid}/jobrequests").get("value", [])
    return sum(1 for r in reqs if r.get("result") is None)  # unfinished = queued or running


def managed_containers() -> list[str]:
    out = _incus("list", PREFIX + "*", "-c", "n", "-f", "csv")
    return [n for n in out.splitlines() if n.startswith(PREFIX)]


def pool_agents(pid: int) -> dict[str, dict]:
    agents = _api(f"pools/{pid}/agents").get("value", [])
    return {a["name"]: a for a in agents if a["name"].startswith(PREFIX)}


def launch_agent(name: str) -> None:
    log(f"launch {name}")
    _incus("launch", f"local:{IMAGE}", name,
           "-c", f"limits.cpu={AGENT_CPU}", "-c", f"limits.memory={AGENT_MEM}",
           "-c", "security.nesting=true", check=True)
    # wait for the container's network
    probe = ["incus", "exec", name, "--", "bash", "-lc",
             "getent hosts dev.azure.com >/dev/null 2>&1"]
    for _ in range(20):
        if subprocess.run(probe, timeout=30).returncode == 0:
            break
        time.sleep(1)
    pat = _pat()
    # register + run as the in-container systemd service (persistent agent)
    reg = (
        "set -e; cd /home/ubuntu/azagent; "
        f"sudo -u ubuntu ./config.sh --unattended --url https://dev.azure.com/{ORG} "
        f"--auth pat --token '{pat}' --pool {POOL_NAME} --agent {name} --replace --acceptTeeEula; "
        "./svc.sh install ubuntu; ./svc.sh start"
    )
    _incus("exec", name, "--", "bash", "-lc", reg, check=True)


def remove_agent(name: str, pid: int, agents: dict[str, dict]) -> None:
    log(f"remove {name}")
    pat = _pat()
    # best-effort in-container deregister, then force-delete the container,
    # then make sure the pool record is gone via the API.
    try:
        _incus("exec", name, "--", "bash", "-lc",
               f"cd /home/ubuntu/azagent && ./svc.sh stop || true; "
               f"sudo -u ubuntu ./config.sh remove --unattended --auth pat --token '{pat}' || true",
               check=False)
    except Exception as exc:  # noqa: BLE001 — teardown is best-effort
        log(f"  deregister warn: {exc}")
    _incus("delete", "-f", name, check=False)
    if name in agents:
        _api_delete(f"pools/{pid}/agents/{agents[name]['id']}")


def _load_idle() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_idle(d: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(d, fh)


def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {msg}", flush=True)


def reconcile() -> None:
    pid = pool_id()
    d = demand(pid)
    now = int(time.time())
    containers = set(managed_containers())
    agents = pool_agents(pid)
    online = {n for n, a in agents.items() if a.get("status") == "online"}
    state = _load_idle()
    unhealthy_since: dict = state.get("unhealthy", {})
    idle: dict = state.get("idle", {})

    # SELF-HEAL: a container that is running but never became an online agent within
    # REGISTER_GRACE_SECS is a stuck/failed registration — reap it so it relaunches fresh.
    for name in list(unhealthy_since):  # forget recovered/vanished containers
        if name not in containers or name in online:
            unhealthy_since.pop(name, None)
    for name in sorted(containers - online):
        since = unhealthy_since.setdefault(name, now)
        if now - since >= REGISTER_GRACE_SECS:
            log(f"reap unhealthy {name}: no online agent after {now - since}s")
            remove_agent(name, pid, agents)
            containers.discard(name)
            unhealthy_since.pop(name, None)

    healthy = sorted(containers & online)
    desired = max(BASELINE, min(MAX_TOTAL, d))
    log(f"demand={d} containers={len(containers)} online={len(healthy)} "
        f"desired={desired} (baseline={BASELINE} cap={MAX_TOTAL})")

    # scale UP — count every live container (healthy + still-registering within grace)
    # so we never over-launch while a fresh agent is mid-registration.
    existing = set(containers)
    for i in range(1, MAX_TOTAL + 1):
        if len(existing) >= desired:
            break
        name = f"{PREFIX}{i}"
        if name not in existing:
            try:
                launch_agent(name)
                existing.add(name)
            except Exception as exc:  # noqa: BLE001 — one bad launch shouldn't wedge the loop
                log(f"  launch {name} FAILED: {exc}")

    # scale DOWN — only ONLINE agents above baseline, lowest-numbered kept, after a grace.
    if d == 0 and len(healthy) > BASELINE:
        for name in healthy[BASELINE:]:
            since = idle.get(name)
            if since is None:
                idle[name] = now
            elif now - since >= IDLE_GRACE_SECS:
                remove_agent(name, pid, agents)
                idle.pop(name, None)
                existing.discard(name)
    else:
        idle = {}  # demand returned (or at/below baseline) — reset all idle timers

    state["unhealthy"] = unhealthy_since
    state["idle"] = idle
    _save_idle(state)


def main() -> int:
    os.makedirs(CONF_DIR, exist_ok=True)
    lock = open(os.path.join(CONF_DIR, ".lock"), "w", encoding="utf-8")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another tick is running; skip")
        return 0
    try:
        reconcile()
    except Exception as exc:  # noqa: BLE001 — never crash the timer; log and retry next tick
        log(f"reconcile ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
