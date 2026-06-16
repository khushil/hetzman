#!/usr/bin/env bash
# bake-ci-agent-image.sh — build a lean Incus *container* image for ephemeral
# Azure DevOps CI agents (project-ci-pool). Container, not VM: ~1-2s launch,
# live cgroup CPU/RAM resize, nested Docker via security.nesting=true.
#
# Lean = the MLE/training/nightly CI toolset only (Python tool-cache + C/PG
# build chain + git + docker + a few CLIs). It deliberately OMITS the CONSTANCE
# BEAM/OTP build (kerl/asdf compile OTP 29 from source — ~20min, unused by CI),
# so the image bakes fast and clones fast.
#
# Output: an Incus image aliased `ado-ci-agent` that the autoscaler clones.
# Idempotent-ish: deletes any prior bake container first; re-publishing replaces
# the alias.
#
# Run as root on the fleet node where the agents live (dc12). Source-of-truth
# toolset mirrors hetzman template ado-ci-agent.yaml minus the asdf-beam step.
set -euo pipefail

BAKE_CT="ci-agent-bake"
IMAGE_ALIAS="ado-ci-agent"
# Seed the Python tool-cache + unpacked ADO agent from a source container. By default
# we bootstrap a throwaway from the *current* ${IMAGE_ALIAS} image, so each re-bake
# chains from the prior image and needs no VM/agent — the pool is self-sustaining once
# the first image exists. Override SRC_AGENT=<running-container> to seed from a specific
# source instead (how the very first image was bootstrapped, from a VM agent).
SRC_AGENT="${SRC_AGENT:-}"
BOOTSTRAP_SRC=""
if [ -z "${SRC_AGENT}" ]; then
  BOOTSTRAP_SRC="ci-agent-bake-src"
  echo "==> [0/6] bootstrap seed container ${BOOTSTRAP_SRC} from image ${IMAGE_ALIAS}"
  incus delete -f "${BOOTSTRAP_SRC}" >/dev/null 2>&1 || true
  incus launch "local:${IMAGE_ALIAS}" "${BOOTSTRAP_SRC}" -c security.nesting=true >/dev/null
  for _ in $(seq 1 30); do
    incus exec "${BOOTSTRAP_SRC}" -- bash -lc 'test -f /home/ubuntu/azagent/agent.tar.gz' && break
    sleep 1
  done
  SRC_AGENT="${BOOTSTRAP_SRC}"
fi
trap '[ -n "${BOOTSTRAP_SRC}" ] && incus delete -f "${BOOTSTRAP_SRC}" >/dev/null 2>&1 || true' EXIT

echo "==> [1/6] fresh nesting container ${BAKE_CT}"
incus delete -f "${BAKE_CT}" >/dev/null 2>&1 || true
incus launch images:ubuntu/24.04 "${BAKE_CT}" \
  -c security.nesting=true -c limits.cpu=4 -c limits.memory=8GiB >/dev/null
# wait for cloud-init / network
for _ in $(seq 1 30); do
  incus exec "${BAKE_CT}" -- bash -lc 'getent hosts github.com >/dev/null 2>&1' && break
  sleep 2
done

echo "==> [2/6] apt toolchain (CI subset)"
incus exec "${BAKE_CT}" -- bash -lc '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q \
    build-essential libpq-dev python3-dev python3.12-venv pkg-config \
    git git-lfs make jq yamllint shellcheck unzip curl ca-certificates lsb-release gnupg
  git lfs install --system
  id ubuntu >/dev/null 2>&1 || useradd -m -s /bin/bash ubuntu
'

echo "==> [3/6] vendor CLIs (gh, az, yq) + docker engine (nesting)"
incus exec "${BAKE_CT}" -- bash -lc '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  install -d -m 0755 /etc/apt/keyrings
  # gh
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg
  chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list
  # az
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg
  chmod go+r /etc/apt/keyrings/microsoft.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/azure-cli.list
  # docker
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo ${VERSION_CODENAME}) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q gh azure-cli docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  getent group docker >/dev/null && usermod -aG docker ubuntu || true
  systemctl enable docker || true
  # yq pinned
  YQ=v4.44.3; curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ}/yq_linux_$(dpkg --print-architecture)" -o /usr/local/bin/yq && chmod +x /usr/local/bin/yq
'

echo "==> [4/6] Python tool-cache (copy the proven, ubuntu-owned cache from ${SRC_AGENT})"
# The actions/python-versions setup.sh path is fragile: it grabbed the wrong Ubuntu
# variant and left the cache empty + root-owned, so UsePythonVersion@0 could neither
# use it (no x64.complete marker) nor rewrite it (EACCES as the ubuntu agent). Copy the
# known-good /opt/hostedtoolcache from the working agent instead, owned by ubuntu.
incus exec "${SRC_AGENT}" -- tar czf /tmp/tc.tgz -C /opt/hostedtoolcache .
incus file pull "${SRC_AGENT}/tmp/tc.tgz" /tmp/tc.tgz
incus exec "${BAKE_CT}" -- bash -lc 'mkdir -p /opt/hostedtoolcache && rm -rf /opt/hostedtoolcache/*'
incus file push /tmp/tc.tgz "${BAKE_CT}/tmp/tc.tgz"
incus exec "${BAKE_CT}" -- bash -lc 'tar xzf /tmp/tc.tgz -C /opt/hostedtoolcache && chown -R ubuntu:ubuntu /opt/hostedtoolcache && rm /tmp/tc.tgz && ls /opt/hostedtoolcache/Python/*/x64.complete'
incus exec "${SRC_AGENT}" -- rm -f /tmp/tc.tgz
rm -f /tmp/tc.tgz

echo "==> [5/6] unpack the proven ADO agent binary (unregistered) + .env"
incus file pull "${SRC_AGENT}/home/ubuntu/azagent/agent.tar.gz" /tmp/agent.tar.gz
incus exec "${BAKE_CT}" -- bash -lc 'mkdir -p /home/ubuntu/azagent && chown -R ubuntu:ubuntu /home/ubuntu'
incus file push /tmp/agent.tar.gz "${BAKE_CT}/home/ubuntu/azagent/agent.tar.gz"
incus exec "${BAKE_CT}" -- bash -lc '
  set -e
  cd /home/ubuntu/azagent
  sudo -u ubuntu tar -xzf agent.tar.gz
  ./bin/installdependencies.sh >/dev/null 2>&1 || true
  printf "LANG=en_US.UTF-8\nAGENT_TOOLSDIRECTORY=/opt/hostedtoolcache\n" > .env
  chown -R ubuntu:ubuntu /home/ubuntu/azagent
'
rm -f /tmp/agent.tar.gz

echo "==> [6/6] publish image alias ${IMAGE_ALIAS}"
incus stop "${BAKE_CT}"
incus image delete "${IMAGE_ALIAS}" >/dev/null 2>&1 || true
incus publish "${BAKE_CT}" --alias "${IMAGE_ALIAS}" --compression zstd \
  --reuse description="Lean ADO CI agent (container; toolset+tool-cache+agent, unregistered)"
incus delete -f "${BAKE_CT}"
echo "DONE: image '${IMAGE_ALIAS}' ready. $(incus image list ${IMAGE_ALIAS} -c as --format compact 2>/dev/null | tail -1)"
