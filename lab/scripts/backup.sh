#!/bin/sh
# Back up /data with restic. BACKUP_TIME back-dates the snapshot (to simulate a
# backup job that stopped running); BACKUP_INTERVAL (seconds) repeats the backup.
set -eu
restic cat config >/dev/null 2>&1 || restic init
if [ -n "$BACKUP_TIME" ]; then
  restic backup /data --host nordmsp --time "$BACKUP_TIME"
else
  restic backup /data --host nordmsp
fi
while :; do
  if [ -n "$BACKUP_INTERVAL" ]; then
    sleep "$BACKUP_INTERVAL"
    restic backup /data --host nordmsp
  else
    sleep 3600
  fi
done
