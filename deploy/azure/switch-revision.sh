#!/usr/bin/env bash
# switch-revision.sh: finish a Conductor revision update after a deployment.
#
# The Conductor app runs in single revision mode with one replica and keeps
# its SQLite registry on the conductor-state share. Single revision mode
# starts the new revision first and stops the old one only once the new one
# is ready, but the old replica holds the registry open, so the new replica
# can fail to open it ("unable to open database file") and never becomes
# ready: the update stalls with the old revision still running (issue #51).
#
# Run this right after `az deployment group create`. When the latest
# revision is not ready within the grace period, it deactivates every other
# active revision so the new one can open the registry, then waits until the
# latest revision is Healthy. The Conductor is down from the deactivation
# until then (observed: 40 s to 2 min); Runner executions are not affected.
# When nothing is stalled, it changes nothing.
#
#   deploy/azure/switch-revision.sh <resource-group> <name-prefix>
#   GRACE_SECONDS=60     how long to wait for the switch to happen on its own
#   TIMEOUT_SECONDS=900  how long to wait for the latest revision to be Healthy
#   POLL_SECONDS=10
#
# Exit status: 0 when the latest revision is Healthy (or nothing needed
# doing), 1 on timeout, 2 on a usage or az error.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: switch-revision.sh <resource-group> <name-prefix>" >&2
  exit 2
fi
rg="$1"
prefix="$2"
app="${prefix}-conductor"
grace="${GRACE_SECONDS:-60}"
timeout="${TIMEOUT_SECONDS:-900}"
poll="${POLL_SECONDS:-10}"

app_field() {
  az containerapp show -g "$rg" -n "$app" --query "properties.$1" -o tsv
}

revision_health() {
  az containerapp revision show -g "$rg" -n "$app" --revision "$1" \
    --query properties.healthState -o tsv
}

latest="$(app_field latestRevisionName)" || exit 2
if [ -z "$latest" ]; then
  echo "error: ${app} in ${rg} has no revision" >&2
  exit 2
fi
echo "latest revision: ${latest}"

# The switch often completes by itself (the old revision is stopped as soon
# as the new one opens the registry); give it the grace period first.
deadline=$((SECONDS + grace))
while :; do
  ready="$(app_field latestReadyRevisionName)" || exit 2
  if [ "$ready" = "$latest" ]; then
    echo "ok: ${latest} is ready; nothing to do"
    exit 0
  fi
  [ "$SECONDS" -lt "$deadline" ] || break
  sleep "$poll"
done

old="$(az containerapp revision list -g "$rg" -n "$app" \
  --query "[?properties.active && name!='${latest}'].name" -o tsv)" || exit 2
if [ -n "$old" ]; then
  for r in $old; do
    echo "deactivating ${r} so that ${latest} can open the registry"
    az containerapp revision deactivate -g "$rg" -n "$app" --revision "$r" -o none || exit 2
  done
else
  echo "no other active revision; waiting for ${latest}"
fi

# Unhealthy / ActivationFailed while the replica backs off is expected.
deadline=$((SECONDS + timeout))
while :; do
  health="$(revision_health "$latest")" || exit 2
  if [ "$health" = "Healthy" ]; then
    echo "ok: ${latest} is Healthy"
    exit 0
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    break
  fi
  echo "waiting: ${latest} is ${health:-unknown}"
  sleep "$poll"
done

echo "error: ${latest} did not become Healthy within ${timeout} s" >&2
if [ -n "$old" ]; then
  echo "the previous revision(s) were deactivated: ${old//$'\n'/ }" >&2
  echo "read the replica logs first; to go back, see README (rollback): a newer Conductor may have migrated the registry" >&2
fi
exit 1
