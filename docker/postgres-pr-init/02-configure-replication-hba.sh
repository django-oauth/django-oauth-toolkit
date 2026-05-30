#!/usr/bin/env bash
set -eu

line='host replication replica all trust'
if ! grep -Fqx "$line" "$PGDATA/pg_hba.conf"; then
  echo "$line" >> "$PGDATA/pg_hba.conf"
fi
