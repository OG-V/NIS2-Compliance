#!/bin/sh
# Back up /data with BorgBackup. BORG_ENCRYPTION chooses the repository's encryption
# (none in the weak profile). BORG_TIME back-dates the archive (to simulate a backup
# job that stopped running); BORG_INTERVAL (seconds) repeats the backup.
set -eu
borg info >/dev/null 2>&1 || borg init --encryption "$BORG_ENCRYPTION"
archive() {
  borg create ${BORG_TIME:+--timestamp "$BORG_TIME"} "::nordmsp-{now:%Y-%m-%dT%H:%M:%S}" /data
}
archive
while :; do
  if [ -n "$BORG_INTERVAL" ]; then
    sleep "$BORG_INTERVAL"
    BORG_TIME="" archive
  else
    sleep 3600
  fi
done
