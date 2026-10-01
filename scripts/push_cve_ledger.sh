#!/usr/bin/env bash
# Update the repository CVE ledger on the huginn-ledger branch from a merged hunt packet.
# Usage: scripts/push_cve_ledger.sh <merged-packet-dir> <hunt-id>
set -euo pipefail
PACKET="$1"
HUNT_ID="$2"
LEDGER_BRANCH="${LEDGER_BRANCH:-huginn-ledger}"

git config user.name "huginn-ledger[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
# Each attempt rebuilds the ledger on the branch's latest tip, so analyst edits pushed
# to candidate_queue.csv while the hunt ran are kept rather than overwritten.
# Registries hunt in separate runs and can finish together, so allow several rebuild/push
# rounds with growing, jittered back-off.
for attempt in 1 2 3 4 5 6; do
  rm -rf ledger-branch && git worktree prune
  if git ls-remote --exit-code --heads origin "$LEDGER_BRANCH" >/dev/null; then
    git fetch --no-tags origin "$LEDGER_BRANCH"
    git worktree add -B "$LEDGER_BRANCH" ledger-branch "origin/$LEDGER_BRANCH"
  else
    git worktree add --orphan -B "$LEDGER_BRANCH" ledger-branch
  fi
  python scripts/update_cve_ledger.py "$PACKET" ledger-branch/ledger --hunt-id "$HUNT_ID"
  git -C ledger-branch add ledger
  if git -C ledger-branch diff --cached --quiet; then
    echo "ledger unchanged"
    exit 0
  fi
  git -C ledger-branch commit -q -m "Hunt ${HUNT_ID}: update CVE ledger"
  if git -C ledger-branch push origin "HEAD:$LEDGER_BRANCH"; then exit 0; fi
  sleep $((attempt * 5 + RANDOM % 10))
done
echo "::error::could not push CVE ledger"
exit 1
