#!/bin/bash

## This script tries to undo some intentional security flaws that were
## implemented for testing. Good luck.
##
## https://gitlab.com/initstring/uptux

if [ "$EUID" -ne 0 ]
  then echo "[!] Please run as root"
  exit
fi

echo "This is going to make delete files created by r00tme. Are you sure?"
read -p "Type YES to continue: "
if [ "$REPLY" != "YES" ]; then
    echo "[+] Smart choice."
    exit
fi

echo ""
echo "[*] Deleting any leftover test vuln unit files..."
for FILE in \
    /lib/systemd/system/uptux-vuln* \
    /usr/bin/uptux-vuln* \
    /tmp/uptux-vuln*
do rm -rf $FILE
done
echo ""

echo "[+] All done, thanks!"
exit 0
