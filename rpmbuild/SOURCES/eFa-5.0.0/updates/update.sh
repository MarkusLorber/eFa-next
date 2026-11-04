#!/bin/bash
# Upgrades from the old eFa 5.0 need the migration tool.
if [ -e /etc/MailScanner/MailScanner.conf ]; then
  echo "ERROR: Direct RPM upgrade from eFa with MailScanner is not supported, use efa-migrate." >&2
  exit 1
fi
exit 0
